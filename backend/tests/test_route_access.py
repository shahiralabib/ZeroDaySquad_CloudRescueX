"""B3 stage 4: the access policy of every route, and what each role can actually do.

``ROUTE_POLICY`` is the single written statement of who may call what. It is checked three ways: against the dependencies
the code really declares (so a new or changed route fails until it is classified here), against the live API for
anonymous callers and for every role, and in end-to-end flows that also check the audit trail.

Roles are ordered viewer < operator < admin. Public routes: GET /health, GET /ready, POST /api/v1/auth/login and the
interactive documentation (served only in the local, demo and test environments).
"""
import json
import logging
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy import func, select

from app.auth import Role
from app.auth_routes import current_principal
from app.config import get_settings
from app.database import (
    AuditEvent,
    DemoFault,
    Escalation,
    HealthCheck,
    Incident,
    IncidentEvent,
    Investigation,
    Notification,
    RecoveryApproval,
    RecoveryExecution,
    Service,
    SimulationState,
    session_factory,
)
from app.main import _request_windows, app, documentation_urls
from auth_support import ANONYMOUS_HEADERS, TEST_PASSWORD, TEST_PASSWORD_HASH

VIEWER, OPERATOR, ADMIN = "viewer", "operator", "admin"
ROLE_LEVEL = {VIEWER: 1, OPERATOR: 2, ADMIN: 3}
USER_OF_ROLE = {VIEWER: "test-viewer", OPERATOR: "test-operator", ADMIN: "test-admin"}
MISSING = 999_999  # an id that does not exist: an allowed caller gets a 404 and nothing is changed

UNAUTHENTICATED = {"detail": {"code": "UNAUTHENTICATED", "message": "Authentication is required, or the credentials are not valid."}}
FORBIDDEN = {"detail": {"code": "FORBIDDEN", "message": "You do not have permission to perform this action."}}

A_FAULT = {"json": {"scenario": "bogus"}}  # rejected by the handler (422) before it changes anything
A_SIMULATION = {"json": {"scenario": "nonexistent", "seed": 1, "event_count": 1}}  # rejected (422) the same way
AN_ACTION = {"json": {"action_id": "restart_demo_application"}}

# (method, path, minimum role, sample request for an id that does not exist)
ROUTE_POLICY = [
    # --- any signed-in user: reads -------------------------------------------------------------------------------------
    ("GET", "/api/v1/auth/me", VIEWER, {}),
    ("GET", "/api/v1/mode", VIEWER, {}),
    ("GET", "/api/v1/overview", VIEWER, {}),
    ("GET", "/api/v1/dashboard/stats", VIEWER, {}),
    ("GET", "/api/v1/threat-intelligence/lookup", VIEWER, {"params": {"indicator": "203.0.113.9"}}),
    ("GET", "/api/v1/simulation/status", VIEWER, {}),
    ("GET", "/api/v1/simulation/resources", VIEWER, {}),
    ("GET", "/api/v1/simulation/resources/{resource_id}", VIEWER, {}),
    ("GET", "/api/v1/simulation/events", VIEWER, {}),
    ("GET", "/api/v1/services", VIEWER, {}),
    ("GET", "/api/v1/services/{service_id}", VIEWER, {}),
    ("GET", "/api/v1/services/{service_id}/health", VIEWER, {}),
    ("GET", "/api/v1/incidents", VIEWER, {}),
    ("GET", "/api/v1/incidents/{incident_id}", VIEWER, {}),
    ("GET", "/api/v1/incidents/{incident_id}/timeline", VIEWER, {}),
    ("GET", "/api/v1/incidents/{incident_id}/investigations", VIEWER, {}),
    ("GET", "/api/v1/incidents/{incident_id}/recovery", VIEWER, {}),
    ("GET", "/api/v1/incidents/{incident_id}/verification", VIEWER, {}),
    ("GET", "/api/v1/incidents/{incident_id}/escalation", VIEWER, {}),
    ("GET", "/api/v1/escalations", VIEWER, {}),
    ("GET", "/api/v1/notifications", VIEWER, {}),
    ("GET", "/api/v1/recovery/actions", VIEWER, {}),
    ("GET", "/api/v1/recovery/executions", VIEWER, {}),
    ("GET", "/api/v1/ai/status", VIEWER, {}),
    ("GET", "/api/v1/demo/scenarios", VIEWER, {}),
    # --- operator: day-to-day operational actions ------------------------------------------------------------------------
    ("POST", "/api/v1/services/{service_id}/health", OPERATOR, {}),
    ("GET", "/api/v1/integrations/status", OPERATOR, {}),  # probes the cloud integrations with the server's credentials
    ("POST", "/api/v1/incidents/{incident_id}/investigations", OPERATOR, {}),
    ("POST", "/api/v1/incidents/{incident_id}/under-investigation", OPERATOR, {}),
    ("POST", "/api/v1/incidents/{incident_id}/acknowledge", OPERATOR, {}),
    ("POST", "/api/v1/incidents/{incident_id}/recovery", OPERATOR, AN_ACTION),
    ("POST", "/api/v1/incidents/{incident_id}/recovery/retry", OPERATOR, AN_ACTION),
    # --- admin: configuration, simulation and fault controls, approval and rejection, manual state changes ---------------
    ("POST", "/api/v1/services", ADMIN, {"json": {}}),
    ("PATCH", "/api/v1/services/{service_id}", ADMIN, {"json": {}}),
    ("PATCH", "/api/v1/incidents/{incident_id}/state", ADMIN, {"json": {"target_state": "RESOLVED"}}),
    ("POST", "/api/v1/incidents/{incident_id}/recovery/approve", ADMIN, AN_ACTION),
    ("POST", "/api/v1/incidents/{incident_id}/reject-recovery", ADMIN, {}),
    ("POST", "/api/v1/simulation/start", ADMIN, A_SIMULATION),
    ("POST", "/api/v1/simulation/tick", ADMIN, {}),
    ("POST", "/api/v1/simulation/stop", ADMIN, {}),
    ("POST", "/api/v1/simulation/reset", ADMIN, {}),
    ("POST", "/api/v1/demo/services/{service_id}/fault", ADMIN, A_FAULT),
    ("POST", "/api/v1/demo/services/{service_id}/reset", ADMIN, {}),
    ("POST", "/api/v1/ai/test", ADMIN, {}),  # a real, authenticated request to the AI provider
]
PUBLIC_ROUTES = [("GET", "/health"), ("GET", "/ready"), ("POST", "/api/v1/auth/login")]
DOCUMENTATION_ROUTES = [("GET", "/docs"), ("GET", "/docs/oauth2-redirect"), ("GET", "/openapi.json"), ("GET", "/redoc")]

# Allowed callers of these really do something (and the suite has other tests that use them), so the matrix only proves
# the refusals for them; the end-to-end flows below prove the allowed path.
CHANGES_STATE_WHEN_ALLOWED = {("POST", "/api/v1/simulation/tick"), ("POST", "/api/v1/simulation/stop"), ("POST", "/api/v1/simulation/reset")}

ROUTE_IDS = [f"{method} {path}" for method, path, _, _ in ROUTE_POLICY]


@pytest.fixture(autouse=True)
def fresh_request_budget():
    """The API limits requests per client address per minute; these tests make many."""
    _request_windows.clear()
    yield
    _request_windows.clear()


def url(template: str) -> str:
    return template.format(resource_id=MISSING, service_id=MISSING, incident_id=MISSING)


def client_for(role: str | None, auth_headers=None, **extra) -> AsyncClient:
    """role=None: anonymous. Otherwise the signed-in test user of that role."""
    headers = dict(ANONYMOUS_HEADERS if role is None else auth_headers(USER_OF_ROLE[role]))
    headers.update(extra)
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers)


async def call(http: AsyncClient, method: str, path: str, request: dict) -> httpx.Response:
    _request_windows.clear()
    return await http.request(method, path, **request)


def is_access_failure(response: httpx.Response) -> bool:
    body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    detail = body.get("detail") if isinstance(body, dict) else None
    return response.status_code in (401, 503) or (response.status_code == 403 and isinstance(detail, dict) and detail.get("code") == "FORBIDDEN")


# --- the policy is complete and matches the code -----------------------------------------------------------------------


def declared_role(route) -> str | None:
    """The strictest role the route's dependencies (its own and its router's) demand; None if it needs no sign-in."""
    levels: list[int] = []

    def walk(dependant) -> None:
        for sub in dependant.dependencies:
            required = getattr(sub.call, "required_role", None)
            if required is not None:
                levels.append(ROLE_LEVEL[Role(required).value])
            elif sub.call is current_principal:
                levels.append(ROLE_LEVEL[VIEWER])
            walk(sub)

    walk(route.dependant)
    return None if not levels else next(name for name, level in ROLE_LEVEL.items() if level == max(levels))


def registered_policy() -> dict[tuple[str, str], str | None]:
    policy: dict[tuple[str, str], str | None] = {}
    for route in app.routes:
        methods = set(getattr(route, "methods", None) or ()) - {"HEAD"}
        role = declared_role(route) if hasattr(route, "dependant") else None
        for method in methods:
            policy[(method, route.path)] = role
    return policy


def test_every_registered_route_has_an_intentional_policy_and_the_code_enforces_it():
    expected: dict[tuple[str, str], str | None] = {(method, template): role for method, template, role, _ in ROUTE_POLICY}
    expected.update({key: None for key in PUBLIC_ROUTES + DOCUMENTATION_ROUTES})
    assert registered_policy() == expected


def test_no_route_is_listed_twice_and_every_policy_row_is_a_known_role():
    keys = [(method, path) for method, path, _, _ in ROUTE_POLICY]
    assert len(keys) == len(set(keys)) and {role for _, _, role, _ in ROUTE_POLICY} <= set(ROLE_LEVEL)


def test_the_router_default_is_signed_in_so_a_route_added_without_a_policy_is_not_public():
    from app.main import api

    assert declared_role(next(route for route in api.routes if route.path == "/mode")) == VIEWER
    public_in_app = {key for key, role in registered_policy().items() if role is None}
    assert public_in_app == set(PUBLIC_ROUTES + DOCUMENTATION_ROUTES)


# --- the live API: anonymous callers and every role ------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "template", "minimum", "sample"), ROUTE_POLICY, ids=ROUTE_IDS)
async def test_anonymous_callers_get_401_on_every_protected_route(method, template, minimum, sample):
    async with client_for(None) as http:
        response = await call(http, method, url(template), sample)
    assert (response.status_code, response.json()) == (401, UNAUTHENTICATED)
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [VIEWER, OPERATOR, ADMIN])
@pytest.mark.parametrize(("method", "template", "minimum", "sample"), ROUTE_POLICY, ids=ROUTE_IDS)
async def test_each_role_is_allowed_exactly_what_its_level_permits(auth_headers, role, method, template, minimum, sample):
    allowed = ROLE_LEVEL[role] >= ROLE_LEVEL[minimum]
    if allowed and (method, template) in CHANGES_STATE_WHEN_ALLOWED:
        pytest.skip("allowed callers change shared simulation state; covered by the end-to-end simulation flow")
    async with client_for(role, auth_headers) as http:
        response = await call(http, method, url(template), sample)
    if allowed:
        assert not is_access_failure(response), (response.status_code, response.text)
        assert response.status_code < 500
    else:
        assert (response.status_code, response.json()) == (403, FORBIDDEN)


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path"), PUBLIC_ROUTES + DOCUMENTATION_ROUTES)
async def test_public_routes_stay_public(method, path):
    async with client_for(None) as http:
        response = await call(http, method, path, {"json": {"username": "nobody", "password": "x"}} if method == "POST" else {})
    assert response.status_code in (200, 401)  # login answers an unknown user with its own generic 401, not UNAUTHENTICATED
    if response.status_code == 401:
        assert response.json()["detail"]["code"] == "INVALID_CREDENTIALS"


def test_documentation_is_served_only_in_the_local_demo_and_test_environments():
    served = {"docs_url": "/docs", "redoc_url": "/redoc", "openapi_url": "/openapi.json"}
    assert all(documentation_urls(name) == served for name in ("local", "demo", "test", "LOCAL", " Demo "))
    hidden = {"docs_url": None, "redoc_url": None, "openapi_url": None}
    assert all(documentation_urls(name) == hidden for name in ("production", "staging", "prod", "", "locals"))
    production = FastAPI(**documentation_urls("production"))
    assert {route.path for route in production.routes} == set()  # not even the schema


def test_the_openapi_document_offers_the_bearer_scheme():
    schema = app.openapi()
    assert schema["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"
    assert schema["paths"]["/api/v1/services"]["get"]["security"] == [{"HTTPBearer": []}]
    assert "security" not in schema["paths"]["/health"]["get"] and "security" not in schema["paths"]["/api/v1/auth/login"]["post"]


# --- nothing but a valid signed token counts -------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "template", "minimum", "sample"), ROUTE_POLICY, ids=ROUTE_IDS)
async def test_the_legacy_admin_header_cannot_substitute_for_a_token(method, template, minimum, sample):
    legacy = {"X-Demo-Admin-Token": get_settings().demo_admin_token}
    async with client_for(None, **legacy) as anonymous, client_for(None, Authorization=f"Bearer {legacy['X-Demo-Admin-Token']}") as shared_token_as_bearer:
        header_only = await call(anonymous, method, url(template), sample)
        as_bearer = await call(shared_token_as_bearer, method, url(template), sample)
    assert (header_only.status_code, header_only.json()) == (401, UNAUTHENTICATED)
    assert (as_bearer.status_code, as_bearer.json()) == (401, UNAUTHENTICATED)


@pytest.mark.asyncio
async def test_the_legacy_header_and_other_client_claims_cannot_raise_a_viewer_above_its_role(auth_headers):
    claims = {"X-Demo-Admin-Token": get_settings().demo_admin_token, "X-Role": "admin", "X-User": "test-admin"}
    async with client_for(VIEWER, auth_headers, **claims) as http:
        admin_route = await call(http, "POST", url("/api/v1/simulation/reset"), {"params": {"role": "admin", "username": "test-admin"}})
        operator_route = await call(http, "POST", url("/api/v1/incidents/{incident_id}/acknowledge"), {"params": {"role": "operator"}})
        who = await call(http, "GET", "/api/v1/auth/me", {})
    assert (admin_route.status_code, admin_route.json()) == (403, FORBIDDEN)
    assert (operator_route.status_code, operator_route.json()) == (403, FORBIDDEN)
    assert who.json() == {"username": "test-viewer", "role": "viewer"}


@pytest.mark.asyncio
async def test_a_legacy_header_next_to_a_valid_token_changes_nothing(auth_headers):
    async with client_for(OPERATOR, auth_headers, **{"X-Demo-Admin-Token": "anything-at-all"}) as http:
        allowed = await call(http, "POST", url("/api/v1/services/{service_id}/health"), {})
        refused = await call(http, "POST", url("/api/v1/simulation/reset"), {})
    assert allowed.status_code == 404 and (refused.status_code, refused.json()) == (403, FORBIDDEN)


@pytest.mark.asyncio
async def test_the_role_that_counts_is_the_one_configured_now_not_the_one_the_token_was_issued_with(monkeypatch):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as admin_client:  # test-admin's token
        before = await call(admin_client, "POST", url("/api/v1/ai/test"), {})
        demoted = [{"username": "test-admin", "role": "viewer", "password_hash": TEST_PASSWORD_HASH}]
        monkeypatch.setattr(get_settings(), "auth_users_json", SecretStr(json.dumps(demoted)))  # as after a restart
        after = await call(admin_client, "POST", url("/api/v1/ai/test"), {})
        read = await call(admin_client, "GET", "/api/v1/services", {})
        removed = [{"username": "someone-else", "role": "admin", "password_hash": TEST_PASSWORD_HASH}]
        monkeypatch.setattr(get_settings(), "auth_users_json", SecretStr(json.dumps(removed)))
        gone = await call(admin_client, "GET", "/api/v1/services", {})
    assert before.status_code == 200
    assert (after.status_code, after.json()) == (403, FORBIDDEN) and read.status_code == 200
    assert (gone.status_code, gone.json()) == (401, UNAUTHENTICATED)


@pytest.mark.asyncio
async def test_protected_routes_answer_503_when_authentication_is_not_configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "auth_secret", SecretStr(""))
    monkeypatch.setattr(get_settings(), "auth_users_json", SecretStr(""))
    async with client_for(None) as http:
        read = await call(http, "GET", "/api/v1/services", {})
        write = await call(http, "POST", url("/api/v1/simulation/reset"), {})
        health = await call(http, "GET", "/health", {})
    expected = {"detail": {"code": "AUTH_NOT_CONFIGURED", "message": "Authentication is not configured."}}
    assert (read.status_code, read.json()) == (503, expected) and (write.status_code, write.json()) == (503, expected)
    assert health.status_code == 200  # the public routes do not depend on authentication


@pytest.mark.asyncio
async def test_a_refusal_never_contains_token_or_configuration_details(auth_headers, caplog):
    token = auth_headers(USER_OF_ROLE[VIEWER])["Authorization"].removeprefix("Bearer ")
    with caplog.at_level(logging.DEBUG):
        async with client_for(VIEWER, auth_headers) as http:
            refused = await call(http, "POST", url("/api/v1/simulation/reset"), {})
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert token not in refused.text and token not in logged and token.split(".")[0] not in logged
    assert "Access denied for test-viewer (viewer): admin role required" in logged
    assert "test-admin" not in refused.text and "scrypt" not in refused.text


# --- end to end: who may do what, and who is on record --------------------------------------------------------------


async def last_audit_id() -> int:
    async with session_factory() as session:
        return await session.scalar(select(func.coalesce(func.max(AuditEvent.id), 0)))


async def audit_since(marker: int, event_type: str) -> list[str]:
    async with session_factory() as session:
        rows = await session.scalars(select(AuditEvent).where(AuditEvent.id > marker, AuditEvent.event_type == event_type).order_by(AuditEvent.id))
        return [row.message for row in rows]


async def make_incident(admin: AsyncClient, scenario: str = "service_unavailable") -> tuple[dict, dict]:
    service = (
        await admin.post("/api/v1/services", json={"name": f"Access {uuid4()}", "environment": "demo", "simulation_status": True, "failure_threshold": 1})
    ).json()
    await admin.post(f"/api/v1/demo/services/{service['id']}/fault", json={"scenario": scenario})
    await admin.post(f"/api/v1/services/{service['id']}/health")
    incident = next(item for item in (await admin.get("/api/v1/incidents")).json() if item["service_id"] == service["id"])
    return service, incident


@pytest.mark.asyncio
async def test_an_operator_executes_a_low_risk_recovery_and_is_named_in_the_audit_trail(auth_headers):
    marker = await last_audit_id()
    async with client_for(ADMIN, auth_headers) as admin, client_for(OPERATOR, auth_headers) as operator, client_for(VIEWER, auth_headers) as viewer:
        _, incident = await make_incident(admin)
        refused = await call(viewer, "POST", f"/api/v1/incidents/{incident['id']}/recovery", AN_ACTION)
        done = await call(operator, "POST", f"/api/v1/incidents/{incident['id']}/recovery", AN_ACTION)
        read = await call(viewer, "GET", f"/api/v1/incidents/{incident['id']}", {})
    assert (refused.status_code, refused.json()) == (403, FORBIDDEN)
    assert done.status_code == 201 and done.json()["status"] == "completed"
    assert read.json()["state"] == "RESOLVED"
    started = [message for message in await audit_since(marker, "recovery.executed") if f"incident {incident['id']} " in message]
    assert started == [f"Recovery restart_demo_application started for incident {incident['id']} by test-operator"]


@pytest.mark.asyncio
async def test_an_admin_approves_a_high_risk_action_and_then_executes_it_themselves(auth_headers):
    marker = await last_audit_id()
    async with client_for(ADMIN, auth_headers) as admin, client_for(OPERATOR, auth_headers) as operator:
        _, incident = await make_incident(admin)
        base = f"/api/v1/incidents/{incident['id']}"
        action = {"json": {"action_id": "reset_demo_environment"}}
        unapproved = await call(admin, "POST", f"{base}/recovery", action)
        operator_cannot_approve = await call(operator, "POST", f"{base}/recovery/approve", action)
        async with session_factory() as session:
            approvals_after_refusal = await session.scalar(select(func.count()).select_from(RecoveryApproval).where(RecoveryApproval.incident_id == incident["id"]))
        approved = await call(admin, "POST", f"{base}/recovery/approve", action)
        executed = await call(admin, "POST", f"{base}/recovery", action)
        reused = await call(admin, "POST", f"{base}/recovery", action)
    assert unapproved.status_code == 409 and unapproved.json()["detail"]["code"] == "APPROVAL_REQUIRED"
    assert (operator_cannot_approve.status_code, operator_cannot_approve.json()) == (403, FORBIDDEN) and approvals_after_refusal == 0
    assert approved.status_code == 200 and executed.status_code == 201
    assert reused.status_code == 409  # the action has run once; a repeat is refused
    async with session_factory() as session:
        approval = await session.scalar(select(RecoveryApproval).where(RecoveryApproval.incident_id == incident["id"]))
    assert approval.approver_principal == "test-admin" and approval.consumed_at is not None
    assert await audit_since(marker, "recovery.approved") == [f"Approved reset_demo_environment for incident {incident['id']} with approval {approval.id} by test-admin"]
    executed_note = [message for message in await audit_since(marker, "recovery.executed") if f"incident {incident['id']} " in message]
    assert executed_note == [f"Recovery reset_demo_environment started for incident {incident['id']} by test-admin"]


@pytest.mark.asyncio
async def test_a_different_user_cannot_consume_another_users_approval(auth_headers, monkeypatch):
    from app.auth import issue_token, load_auth_config

    users = [{"username": name, "role": role, "password_hash": TEST_PASSWORD_HASH} for name, role in
             (("test-admin", "admin"), ("test-admin-2", "admin"), ("test-operator", "operator"))]
    monkeypatch.setattr(get_settings(), "auth_users_json", SecretStr(json.dumps(users)))
    config = load_auth_config()

    def headers_of(name: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {issue_token(config, config.users[name]).token}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers_of("test-admin")) as approver, \
            AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers_of("test-admin-2")) as other_admin, \
            AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=headers_of("test-operator")) as operator:
        action = {"json": {"action_id": "reset_demo_environment"}}

        async def approved_incident() -> dict:
            _, incident = await make_incident(approver)
            approved = await call(approver, "POST", f"/api/v1/incidents/{incident['id']}/recovery/approve", action)
            assert approved.status_code == 200
            return incident

        async def approval_and_executions(incident: dict):
            async with session_factory() as session:
                approval = await session.scalar(select(RecoveryApproval).where(RecoveryApproval.incident_id == incident["id"]))
                executions = await session.scalar(select(func.count()).select_from(RecoveryExecution).where(RecoveryExecution.incident_id == incident["id"]))
            return approval, executions

        # A refused attempt escalates its incident, so each refused user gets an incident of their own.
        by_operator_incident, by_other_admin_incident = await approved_incident(), await approved_incident()
        by_operator = await call(operator, "POST", f"/api/v1/incidents/{by_operator_incident['id']}/recovery", action)
        by_other_admin = await call(other_admin, "POST", f"/api/v1/incidents/{by_other_admin_incident['id']}/recovery", action)
        for refused, incident in ((by_operator, by_operator_incident), (by_other_admin, by_other_admin_incident)):
            approval, executions = await approval_and_executions(incident)
            assert refused.status_code == 409 and refused.json()["detail"]["code"] == "APPROVAL_REQUIRED"
            # not their approval: nothing ran and the approval is untouched
            assert approval.approver_principal == "test-admin" and approval.consumed_at is None and approval.revoked is False and executions == 0
        # the approver can still use it: the refusals did not consume it (retry reopens an incident the refusal escalated)
        by_approver = await call(approver, "POST", f"/api/v1/incidents/{by_operator_incident['id']}/recovery/retry", action)
        approval, executions = await approval_and_executions(by_operator_incident)
    assert by_approver.status_code == 201 and approval.consumed_at is not None and executions == 1

@pytest.mark.asyncio
async def test_each_admin_can_use_their_own_approval(auth_headers, monkeypatch):
    from app.auth import issue_token, load_auth_config

    users = [{"username": name, "role": "admin", "password_hash": TEST_PASSWORD_HASH} for name in ("test-admin", "test-admin-2")]
    monkeypatch.setattr(get_settings(), "auth_users_json", SecretStr(json.dumps(users)))
    config = load_auth_config()
    second = {"Authorization": f"Bearer {issue_token(config, config.users['test-admin-2']).token}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=second) as admin_two:
        _, incident = await make_incident(admin_two)
        base = f"/api/v1/incidents/{incident['id']}"
        action = {"json": {"action_id": "reset_demo_environment"}}
        approved = await call(admin_two, "POST", f"{base}/recovery/approve", action)
        executed = await call(admin_two, "POST", f"{base}/recovery", action)
    assert approved.status_code == 200 and executed.status_code == 201

@pytest.mark.asyncio
async def test_an_approval_does_not_cover_a_different_action_or_parameters_or_incident(auth_headers):
    async with client_for(ADMIN, auth_headers) as admin, client_for(OPERATOR, auth_headers) as operator:
        _, incident = await make_incident(admin)
        _, other = await make_incident(admin)
        base = f"/api/v1/incidents/{incident['id']}"
        await call(admin, "POST", f"{base}/recovery/approve", {"json": {"action_id": "reset_demo_environment"}})
        different_action = await call(operator, "POST", f"{base}/recovery", {"json": {"action_id": "restore_known_good_configuration"}})
        different_incident = await call(operator, "POST", f"/api/v1/incidents/{other['id']}/recovery", {"json": {"action_id": "reset_demo_environment"}})
    assert different_action.status_code == 409 and different_incident.status_code == 409
    assert different_incident.json()["detail"]["code"] == "APPROVAL_REQUIRED"


async def escalated(admin: AsyncClient, operator: AsyncClient) -> dict:
    _, incident = await make_incident(admin)
    refused_by_policy = await call(operator, "POST", f"/api/v1/incidents/{incident['id']}/recovery", {"json": {"action_id": "restart_demo_application", "parameters": {"unexpected": True}}})
    assert refused_by_policy.status_code == 409
    return incident


@pytest.mark.asyncio
async def test_acknowledgement_is_an_operator_action_recorded_under_the_authenticated_name(auth_headers):
    marker = await last_audit_id()
    async with client_for(ADMIN, auth_headers) as admin, client_for(OPERATOR, auth_headers) as operator, client_for(VIEWER, auth_headers) as viewer:
        incident = await escalated(admin, operator)
        path = f"/api/v1/incidents/{incident['id']}/acknowledge"
        by_viewer = await call(viewer, "POST", path, {})
        still_pending = (await call(viewer, "GET", "/api/v1/escalations", {"params": {"status": "pending"}})).json()
        spoofed = await call(operator, "POST", path, {"params": {"administrator": "mallory"}})  # a supplied name is ignored
        timeline = (await call(operator, "GET", f"/api/v1/incidents/{incident['id']}/timeline", {})).json()
    assert (by_viewer.status_code, by_viewer.json()) == (403, FORBIDDEN)
    assert incident["id"] in {item["incident_id"] for item in still_pending}
    assert spoofed.status_code == 200 and spoofed.json()["assigned_administrator"] == "test-operator"
    messages = [message for message in await audit_since(marker, "escalation.acknowledged")]
    assert any(message.endswith("acknowledged by test-operator") for message in messages)
    assert not any("mallory" in message for message in messages)
    assert [event["metadata"]["administrator"] for event in timeline if event["event_type"] == "ADMIN_ACKNOWLEDGED"] == ["test-operator"]


@pytest.mark.asyncio
async def test_rejection_is_admin_only_and_recorded_under_the_authenticated_name(auth_headers):
    marker = await last_audit_id()
    async with client_for(ADMIN, auth_headers) as admin, client_for(OPERATOR, auth_headers) as operator:
        incident = await escalated(admin, operator)
        path = f"/api/v1/incidents/{incident['id']}/reject-recovery"
        by_operator = await call(operator, "POST", path, {"params": {"reason": "no"}})
        by_admin = await call(admin, "POST", path, {"params": {"reason": "Too risky", "administrator": "x" * 500}})
    assert (by_operator.status_code, by_operator.json()) == (403, FORBIDDEN)
    assert by_admin.status_code == 200 and by_admin.json()["status"] == "rejected" and by_admin.json()["assigned_administrator"] == "test-admin"
    messages = await audit_since(marker, "recovery.rejected")
    assert any(f"incident {incident['id']} " in message and "by test-admin: Too risky" in message for message in messages)


@pytest.mark.asyncio
async def test_marking_under_investigation_is_an_operator_action_and_audited(auth_headers):
    marker = await last_audit_id()
    async with client_for(ADMIN, auth_headers) as admin, client_for(OPERATOR, auth_headers) as operator, client_for(VIEWER, auth_headers) as viewer:
        _, incident = await make_incident(admin)
        path = f"/api/v1/incidents/{incident['id']}/under-investigation"
        by_viewer = await call(viewer, "POST", path, {})
        unchanged = (await call(viewer, "GET", f"/api/v1/incidents/{incident['id']}", {})).json()["state"]
        by_operator = await call(operator, "POST", path, {})
    assert by_viewer.status_code == 403 and unchanged == "DETECTED"
    assert by_operator.status_code == 200 and by_operator.json()["state"] == "INVESTIGATING"
    assert await audit_since(marker, "incident.under_investigation") == [f"Incident {incident['id']} marked under investigation by test-operator"]


@pytest.mark.asyncio
async def test_investigations_are_an_operator_action_recorded_with_the_starting_user(auth_headers):
    marker = await last_audit_id()
    async with client_for(ADMIN, auth_headers) as admin, client_for(OPERATOR, auth_headers) as operator, client_for(VIEWER, auth_headers) as viewer:
        _, incident = await make_incident(admin)
        path = f"/api/v1/incidents/{incident['id']}/investigations"
        by_viewer = await call(viewer, "POST", path, {})
        none_yet = (await call(viewer, "GET", path, {})).json()
        started = await call(operator, "POST", path, {})
        timeline = (await call(viewer, "GET", f"/api/v1/incidents/{incident['id']}/timeline", {})).json()
    assert by_viewer.status_code == 403 and none_yet == []
    assert started.status_code == 201
    assert [event["metadata"]["started_by"] for event in timeline if event["event_type"] == "INVESTIGATION_STARTED"] == ["test-operator"]
    assert any(message.endswith("by test-operator") and f"incident {incident['id']} " in message for message in await audit_since(marker, "investigation.started"))


@pytest.mark.asyncio
async def test_manual_state_changes_are_admin_only_and_audited(auth_headers):
    marker = await last_audit_id()
    async with client_for(ADMIN, auth_headers) as admin, client_for(OPERATOR, auth_headers) as operator:
        _, incident = await make_incident(admin)
        path = f"/api/v1/incidents/{incident['id']}/state"
        by_operator = await call(operator, "PATCH", path, {"json": {"target_state": "INVESTIGATING"}})
        unchanged = (await call(operator, "GET", f"/api/v1/incidents/{incident['id']}", {})).json()["state"]
        by_admin = await call(admin, "PATCH", path, {"json": {"target_state": "INVESTIGATING", "description": "Taking over"}})
    assert by_operator.status_code == 403 and unchanged == "DETECTED"
    assert by_admin.status_code == 200 and by_admin.json()["state"] == "INVESTIGATING"
    assert await audit_since(marker, "incident.state_changed") == [f"Incident {incident['id']} moved DETECTED -> INVESTIGATING by test-admin"]


@pytest.mark.asyncio
async def test_service_configuration_is_admin_only_and_audited(auth_headers):
    marker = await last_audit_id()
    name = f"Config {uuid4()}"
    body = {"name": name, "environment": "demo", "simulation_status": True}
    async with client_for(ADMIN, auth_headers) as admin, client_for(OPERATOR, auth_headers) as operator, client_for(VIEWER, auth_headers) as viewer:
        refused = [await call(who, "POST", "/api/v1/services", {"json": body}) for who in (viewer, operator)]
        names_after_refusals = [item["name"] for item in (await call(viewer, "GET", "/api/v1/services", {})).json()]
        created = await call(admin, "POST", "/api/v1/services", {"json": body})
        service_id = created.json()["id"]
        patch_refused = await call(operator, "PATCH", f"/api/v1/services/{service_id}", {"json": {"failure_threshold": 9}})
        unchanged = (await call(viewer, "GET", f"/api/v1/services/{service_id}", {})).json()["failure_threshold"]
        patched = await call(admin, "PATCH", f"/api/v1/services/{service_id}", {"json": {"failure_threshold": 4}})
    assert [response.status_code for response in refused] == [403, 403] and name not in names_after_refusals
    assert created.status_code == 201 and patch_refused.status_code == 403 and unchanged != 9
    assert patched.status_code == 200 and patched.json()["failure_threshold"] == 4
    assert await audit_since(marker, "service.created") == [f"Service {service_id} ({name}) created by test-admin"]
    assert await audit_since(marker, "service.updated") == [f"Service {service_id} updated (fields: failure_threshold) by test-admin"]


@pytest.mark.asyncio
async def test_fault_injection_and_reset_are_admin_only_and_audited(auth_headers):
    marker = await last_audit_id()
    async with client_for(ADMIN, auth_headers) as admin, client_for(OPERATOR, auth_headers) as operator:
        service, _ = await make_incident(admin)
        path = f"/api/v1/demo/services/{service['id']}"
        refused = [await call(operator, "POST", f"{path}/fault", {"json": {"scenario": "healthy"}}), await call(operator, "POST", f"{path}/reset", {})]
        async with session_factory() as session:
            still = (await session.scalar(select(DemoFault).where(DemoFault.service_id == service["id"]))).scenario
        reset = await call(admin, "POST", f"{path}/reset", {})
    assert [response.status_code for response in refused] == [403, 403] and still == "service_unavailable"
    assert reset.status_code == 200
    assert await audit_since(marker, "demo.fault_reset") == [f"Service {service['id']} fault reset to healthy by test-admin"]
    assert await audit_since(marker, "demo.fault_injected") == [f"Fault service_unavailable injected into service {service['id']} by test-admin"]


@pytest.mark.asyncio
async def test_simulation_controls_are_admin_only_and_audited(auth_headers):
    marker = await last_audit_id()
    start = {"json": {"scenario": "authentication_attack", "seed": 42, "event_count": 6}}
    async with client_for(ADMIN, auth_headers) as admin, client_for(OPERATOR, auth_headers) as operator:
        refused = [await call(operator, "POST", f"/api/v1/simulation/{action}", start if action == "start" else {}) for action in ("start", "tick", "stop", "reset")]
        reset = await call(admin, "POST", "/api/v1/simulation/reset", {})
        started = await call(admin, "POST", "/api/v1/simulation/start", start)
        ticked = await call(admin, "POST", "/api/v1/simulation/tick", {})
        stopped = await call(admin, "POST", "/api/v1/simulation/stop", {})
        final_reset = await call(admin, "POST", "/api/v1/simulation/reset", {})
    assert [response.status_code for response in refused] == [403] * 4
    assert [response.status_code for response in (reset, started, ticked, stopped, final_reset)] == [200] * 5
    for event_type in ("simulation.started", "simulation.tick", "simulation.stopped"):
        assert [message.endswith("by test-admin") for message in await audit_since(marker, event_type)] == [True]
    assert [message.endswith("by test-admin") for message in await audit_since(marker, "simulation.reset")] == [True, True]


@pytest.mark.asyncio
async def test_a_login_issued_token_works_on_a_protected_route():
    async with client_for(None) as http:
        login = await call(http, "POST", "/api/v1/auth/login", {"json": {"username": "test-operator", "password": TEST_PASSWORD}})
        token = login.json()["access_token"]
        allowed = await call(http, "GET", "/api/v1/services", {"headers": {"Authorization": f"Bearer {token}"}})
        refused = await call(http, "POST", "/api/v1/simulation/reset", {"headers": {"Authorization": f"Bearer {token}"}})
    assert login.status_code == 200 and allowed.status_code == 200 and refused.status_code == 403


# --- a refusal changes nothing ---------------------------------------------------------------------------------------


async def snapshot() -> dict:
    async with session_factory() as session:
        counts = {
            model.__name__: await session.scalar(select(func.count()).select_from(model))
            for model in (Service, Incident, IncidentEvent, AuditEvent, Escalation, RecoveryApproval, RecoveryExecution, Investigation, DemoFault, Notification, HealthCheck)
        }
        counts["incidents"] = sorted((row.id, row.state, row.escalation_status) for row in await session.scalars(select(Incident)))
        counts["services"] = sorted((row.id, row.name, row.status, row.failure_threshold, row.simulation_status) for row in await session.scalars(select(Service)))
        counts["faults"] = sorted((row.service_id, row.scenario) for row in await session.scalars(select(DemoFault)))
        counts["escalations"] = sorted((row.id, row.acknowledged, row.assigned_administrator) for row in await session.scalars(select(Escalation)))
        counts["simulation"] = sorted((row.scenario, row.status, row.tick_count) for row in await session.scalars(select(SimulationState)))
        return counts


def mutating_requests(service_id: int, incident_id: int) -> list[tuple[str, str, str, dict]]:
    incident, service = f"/api/v1/incidents/{incident_id}", f"/api/v1/services/{service_id}"
    return [
        ("POST", "/api/v1/services", ADMIN, {"json": {"name": f"Never created {uuid4()}", "environment": "demo", "simulation_status": True}}),
        ("PATCH", service, ADMIN, {"json": {"name": "Renamed by a refused caller", "failure_threshold": 9}}),
        ("POST", f"{service}/health", OPERATOR, {}),
        ("PATCH", f"{incident}/state", ADMIN, {"json": {"target_state": "INVESTIGATING"}}),
        ("POST", f"{incident}/investigations", OPERATOR, {}),
        ("POST", f"{incident}/under-investigation", OPERATOR, {}),
        ("POST", f"{incident}/acknowledge", OPERATOR, {}),
        ("POST", f"{incident}/reject-recovery", ADMIN, {"params": {"reason": "refused"}}),
        ("POST", f"{incident}/recovery/approve", ADMIN, {"json": {"action_id": "reset_demo_environment"}}),
        ("POST", f"{incident}/recovery", OPERATOR, {"json": {"action_id": "restart_demo_application"}}),
        ("POST", f"{incident}/recovery/retry", OPERATOR, {"json": {"action_id": "restart_demo_application"}}),
        ("POST", f"/api/v1/demo/services/{service_id}/fault", ADMIN, {"json": {"scenario": "healthy"}}),
        ("POST", f"/api/v1/demo/services/{service_id}/reset", ADMIN, {}),
        ("POST", "/api/v1/simulation/start", ADMIN, {"json": {"scenario": "authentication_attack", "seed": 7, "event_count": 5}}),
        ("POST", "/api/v1/simulation/tick", ADMIN, {}),
        ("POST", "/api/v1/simulation/stop", ADMIN, {}),
        ("POST", "/api/v1/simulation/reset", ADMIN, {}),
        ("POST", "/api/v1/ai/test", ADMIN, {}),
    ]


@pytest.mark.asyncio
async def test_refused_requests_change_nothing_in_the_database(auth_headers):
    async with client_for(ADMIN, auth_headers) as admin:
        service, incident = await make_incident(admin)
        await call(admin, "GET", "/api/v1/simulation/status", {})  # make sure the simulation row exists before the snapshot
    requests = mutating_requests(service["id"], incident["id"])
    before = await snapshot()
    refusals = 0
    for caller in (None, VIEWER, OPERATOR):
        async with client_for(caller, auth_headers) as http:
            for method, path, minimum, request in requests:
                if caller == OPERATOR and minimum == OPERATOR:
                    continue  # an operator is allowed these; the others are the refusals under test
                response = await call(http, method, path, request)
                expected = (401, UNAUTHENTICATED) if caller is None else (403, FORBIDDEN)
                assert (response.status_code, response.json()) == expected, (caller, method, path)
                refusals += 1
    assert refusals == 3 * len(requests) - sum(1 for _, _, minimum, _ in requests if minimum == OPERATOR)
    assert await snapshot() == before
