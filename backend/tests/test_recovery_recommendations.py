"""Incident-specific recovery recommendations, and what executing an action may change."""
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.config import get_settings
from app.database import Incident, Service, session_factory
from app.main import _request_windows, app
from app.recovery import ACTION_CATALOG
from app.remediation import (
    CREDENTIAL_ATTACK,
    DETECTION_RULE_CATEGORY,
    ESCALATE_TO_ADMINISTRATOR,
    NETWORK,
    NO_ACTION,
    OUTAGE_FAULT_CATEGORY,
    SATURATION_PERCENT,
    action_addresses,
    recommend_telemetry_action,
)

ADMIN = {"X-Demo-Admin-Token": "local-demo-admin"}
RESTORE_CONFIG = "restore_known_good_configuration"
RESTORE_DEPENDENCY = "restore_demo_dependency"
RESTART = "restart_demo_application"
SCALE = "scale_demo_application"
ESCALATE = ESCALATE_TO_ADMINISTRATOR
RESOURCE_TYPES = ["firewall", "vpn_gateway", "web_server", "authentication_service", "database_server"]


@pytest.fixture(autouse=True)
def clear_rate_limit_window():
    _request_windows.clear()


def new_client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def run_scenario(client: AsyncClient, scenario: str) -> list[dict]:
    assert (await client.post("/api/v1/simulation/reset", headers=ADMIN)).status_code == 200
    before = {item["id"] for item in (await client.get("/api/v1/incidents")).json()}
    started = await client.post(
        "/api/v1/simulation/start", headers=ADMIN, json={"scenario": scenario, "seed": 42, "event_count": 10}
    )
    assert started.status_code == 200
    return [item for item in (await client.get("/api/v1/incidents")).json() if item["id"] not in before]


def on_resource(incidents: list[dict], resource_key: str) -> list[dict]:
    return [item for item in incidents if item["diagnostic_evidence"]["resource_key"] == resource_key]


async def investigate(client: AsyncClient, incident_id: int) -> dict:
    response = await client.post(f"/api/v1/incidents/{incident_id}/investigations")
    assert response.status_code == 201
    return response.json()


async def get_incident(client: AsyncClient, incident_id: int) -> dict:
    return (await client.get(f"/api/v1/incidents/{incident_id}")).json()


async def resources(client: AsyncClient) -> dict[str, dict]:
    return {item["resource_key"]: item for item in (await client.get("/api/v1/simulation/resources")).json()}


async def run_action(client: AsyncClient, incident_id: int, action_id: str):
    """Approve (when the action needs it) and execute, the way the UI does.

    A low-risk action on an escalated incident cannot be approved, so it goes through the retry endpoint, which is
    how the Escalations page re-opens an incident for an administrator-authorised attempt.
    """
    parameters = {"instances": 1} if action_id == SCALE else {}
    if ACTION_CATALOG[action_id].risk == "low" and (await get_incident(client, incident_id))["state"] == "ESCALATED":
        return await client.post(
            f"/api/v1/incidents/{incident_id}/recovery/retry",
            headers=ADMIN,
            json={"action_id": action_id, "parameters": parameters, "approved": True},
        )
    if ACTION_CATALOG[action_id].risk != "low":
        approval = await client.post(
            f"/api/v1/incidents/{incident_id}/recovery/approve",
            headers=ADMIN,
            json={"action_id": action_id, "parameters": parameters},
        )
        assert approval.status_code == 200
    return await client.post(
        f"/api/v1/incidents/{incident_id}/recovery", headers=ADMIN, json={"action_id": action_id, "parameters": parameters}
    )


async def latest_verification(client: AsyncClient, incident_id: int) -> dict:
    return max((await client.get(f"/api/v1/incidents/{incident_id}/verification")).json(), key=lambda item: item["id"])


def expected_capacity_action(incident: dict) -> str:
    metadata = incident["diagnostic_evidence"]["metadata"]
    peak = max(metadata["cpu_percent"], metadata["memory_percent"])
    return SCALE if peak >= SATURATION_PERCENT else RESTART


# --- Telemetry incidents: every rule, on the resource it affects -----------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "resource_key", "expected"),
    [
        ("authentication_attack", "sim-auth-01", ESCALATE),
        ("network_disruption", "sim-firewall-01", ESCALATE),
        ("network_disruption", "sim-vpn-01", ESCALATE),
        ("unusual_traffic", "sim-firewall-01", ESCALATE),
        ("configuration_drift", "sim-firewall-01", RESTORE_CONFIG),
        ("configuration_drift", "sim-vpn-01", RESTORE_CONFIG),
        ("configuration_drift", "sim-web-01", RESTORE_CONFIG),
        ("configuration_drift", "sim-auth-01", RESTORE_CONFIG),
        ("configuration_drift", "sim-db-01", RESTORE_CONFIG),
        ("dependency_failure", "sim-db-01", RESTORE_DEPENDENCY),
        ("resource_pressure", "sim-db-01", ESCALATE),  # restart/scale only act on the web tier
    ],
)
async def test_each_incident_type_gets_the_recommendation_its_evidence_supports(scenario, resource_key, expected):
    async with new_client() as client:
        incidents = on_resource(await run_scenario(client, scenario), resource_key)
        assert incidents
        investigations = [(item, await investigate(client, item["id"])) for item in incidents]

    for incident, investigation in investigations:
        result = investigation["result"]
        assert investigation["status"] == "completed" and investigation["confidence"] >= get_settings().ai_confidence_threshold
        assert result["recommended_action"] == expected, (incident["detection_rule"], result["reason_for_recommendation"])
        if expected == ESCALATE:
            assert result["recommended_action"] != RESTORE_CONFIG  # never pretend configuration restore contains an attack
            assert result["human_intervention_recommended"] is True


@pytest.mark.asyncio
async def test_capacity_incident_on_the_web_tier_scales_only_when_the_evidence_shows_saturation():
    async with new_client() as client:
        incident = on_resource(await run_scenario(client, "resource_pressure"), "sim-web-01")[0]
        result = (await investigate(client, incident["id"]))["result"]

    assert result["recommended_action"] == expected_capacity_action(incident)
    metadata = incident["diagnostic_evidence"]["metadata"]
    assert f"{max(metadata['cpu_percent'], metadata['memory_percent']):g}%" in result["reason_for_recommendation"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fault", "expected"),
    [("service_unavailable", RESTART), ("configuration_failure", RESTORE_CONFIG), ("dependency_unavailable", RESTORE_DEPENDENCY)],
)
async def test_outage_incidents_get_the_action_for_their_injected_fault(fault, expected):
    async with new_client() as client:
        service = (
            await client.post(
                "/api/v1/services",
                json={"name": f"Recommend {uuid4()}", "environment": "demo", "simulation_status": True, "failure_threshold": 1},
            )
        ).json()
        await client.post(f"/api/v1/demo/services/{service['id']}/fault", headers=ADMIN, json={"scenario": fault})
        incident = next(i for i in (await client.get("/api/v1/incidents")).json() if i["service_id"] == service["id"])
        investigation = await investigate(client, incident["id"])
        executed = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery/approve", headers=ADMIN, json={"action_id": expected}
        )
        outcome = await run_action(client, incident["id"], expected) if executed.status_code == 409 else None
        if executed.status_code == 200:
            outcome = await client.post(f"/api/v1/incidents/{incident['id']}/recovery", headers=ADMIN, json={"action_id": expected})
        verification = await latest_verification(client, incident["id"])

    assert investigation["result"]["recommended_action"] == expected
    assert outcome.status_code == 201 and verification["outcome"] == "VERIFIED_SUCCESS"


# --- Credential attacks and network anomalies are escalated, not "fixed" ---------------------------------------------


@pytest.mark.asyncio
async def test_authentication_attack_creates_an_administrator_escalation_with_manual_containment_steps():
    async with new_client() as client:
        incidents = await run_scenario(client, "authentication_attack")
        for incident in incidents:
            await investigate(client, incident["id"])
        escalations = (await client.get("/api/v1/escalations")).json()
        notifications = (await client.get("/api/v1/notifications")).json()
        states = [(await get_incident(client, i["id"])) for i in incidents]

    assert {i["detection_rule"] for i in incidents} == {"repeated_failed_authentication", "suspicious_login_pattern"}
    for incident, state in zip(incidents, states):
        assert state["state"] == "ESCALATED" and state["escalation_status"] == "created"
        assert state["recovery_recommendation"] == ESCALATE and state["resolution_timestamp"] is None
        escalation = next(e for e in escalations if e["incident_id"] == incident["id"])
        assert "administrator escalation" in escalation["reason"]
        assert "lock or reset the affected accounts" in escalation["recommended_next_steps"]
        assert "revoke active sessions" in escalation["recommended_next_steps"]
        assert any(n["incident_id"] == incident["id"] for n in notifications)


@pytest.mark.asyncio
async def test_network_anomaly_is_escalated_with_network_specific_steps():
    async with new_client() as client:
        incident = on_resource(await run_scenario(client, "unusual_traffic"), "sim-firewall-01")[0]
        await investigate(client, incident["id"])
        escalation = next(e for e in (await client.get("/api/v1/escalations")).json() if e["incident_id"] == incident["id"])

    assert "firewall and VPN logs" in escalation["recommended_next_steps"]


@pytest.mark.asyncio
@pytest.mark.parametrize("wrong_action", [RESTORE_CONFIG, RESTART, RESTORE_DEPENDENCY, "reset_demo_environment"])
async def test_no_recovery_action_can_resolve_a_credential_attack(wrong_action):
    async with new_client() as client:
        incident = next(
            i for i in await run_scenario(client, "authentication_attack") if i["detection_rule"] == "repeated_failed_authentication"
        )
        await investigate(client, incident["id"])
        response = await run_action(client, incident["id"], wrong_action)
        verification = await latest_verification(client, incident["id"])
        state = await get_incident(client, incident["id"])
        assets = await resources(client)

    assert response.status_code == 201  # the simulated action ran...
    assert verification["outcome"] == "VERIFICATION_FAILED"  # ...but cannot be verified
    assert state["state"] == "ESCALATED" and state["resolution_timestamp"] is None
    assert assets["sim-auth-01"]["status"] == "degraded"


# --- What executing an action may change -----------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "resource_key"),
    [("configuration_drift", "sim-firewall-01"), ("dependency_failure", "sim-db-01"), ("resource_pressure", "sim-web-01")],
)
async def test_the_recommended_action_resolves_its_incident_and_changes_only_its_resource(scenario, resource_key):
    async with new_client() as client:
        incidents = await run_scenario(client, scenario)
        incident = on_resource(incidents, resource_key)[0]
        recommended = (await investigate(client, incident["id"]))["result"]["recommended_action"]
        before = await resources(client)
        response = await run_action(client, incident["id"], recommended)
        verification = await latest_verification(client, incident["id"])
        state = await get_incident(client, incident["id"])
        after = await resources(client)
        others = [await get_incident(client, i["id"]) for i in incidents if i["id"] != incident["id"]]

    assert recommended in ACTION_CATALOG
    assert response.status_code == 201
    assert verification["outcome"] == "VERIFIED_SUCCESS" and state["state"] == "RESOLVED"
    assert before[resource_key]["status"] == "degraded" and after[resource_key]["status"] == "healthy"
    for key, asset in before.items():
        if key != resource_key:
            assert after[key]["status"] == asset["status"], f"{key} must not be touched"
    assert all(other["state"] != "RESOLVED" for other in others)  # unrelated incidents are not resolved


@pytest.mark.asyncio
async def test_scaling_sets_one_instance_on_the_web_server_only():
    async with new_client() as client:
        incidents = await run_scenario(client, "resource_pressure")
        web = on_resource(incidents, "sim-web-01")[0]
        await investigate(client, web["id"])
        response = await run_action(client, web["id"], SCALE)
        verification = await latest_verification(client, web["id"])
        after = await resources(client)

    assert response.status_code == 201 and verification["outcome"] == "VERIFIED_SUCCESS"
    assert after["sim-web-01"]["status"] == "healthy" and after["sim-web-01"]["metadata"]["instances"] == 1
    assert after["sim-db-01"]["status"] == "degraded" and "instances" not in after["sim-db-01"]["metadata"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "resource_key", "wrong_action"),
    [
        ("resource_pressure", "sim-db-01", RESTART),  # restart acts on the web application, not a database
        ("resource_pressure", "sim-db-01", SCALE),
        ("configuration_drift", "sim-firewall-01", RESTORE_DEPENDENCY),  # dependency restore only covers db/auth services
        ("configuration_drift", "sim-web-01", RESTORE_DEPENDENCY),
        ("dependency_failure", "sim-db-01", RESTORE_CONFIG),  # a configuration restore does not bring a dependency back
        ("dependency_failure", "sim-db-01", RESTART),
        ("unusual_traffic", "sim-firewall-01", RESTORE_CONFIG),
        ("network_disruption", "sim-vpn-01", RESTORE_CONFIG),
    ],
)
async def test_an_action_that_does_not_fit_the_incident_or_resource_type_fails_verification(scenario, resource_key, wrong_action):
    async with new_client() as client:
        incident = on_resource(await run_scenario(client, scenario), resource_key)[0]
        await investigate(client, incident["id"])
        before = await resources(client)
        await run_action(client, incident["id"], wrong_action)
        verification = await latest_verification(client, incident["id"])
        state = await get_incident(client, incident["id"])
        after = await resources(client)

    assert verification["outcome"] == "VERIFICATION_FAILED"
    assert state["state"] == "ESCALATED" and state["resolution_timestamp"] is None
    assert {key: asset["status"] for key, asset in after.items()} == {key: asset["status"] for key, asset in before.items()}


@pytest.mark.asyncio
async def test_fixing_one_incident_does_not_resolve_other_incidents_on_the_same_resource():
    async with new_client() as client:
        credential = await run_scenario(client, "authentication_attack")  # degrades sim-auth-01
        async with session_factory() as session:
            service = await session.scalar(select(Service).where(Service.name == "Checkout API"))
            drift = Incident(
                service_id=service.id,
                incident_type="configuration_change",
                severity="medium",
                state="INVESTIGATING",
                summary="Configuration changed on the authentication service",
                diagnostic_evidence=json.dumps(
                    {"event_id": str(uuid4()), "resource_key": "sim-auth-01", "metadata": {"setting": "access_policy"}}
                ),
                deduplication_key=f"same-resource-{uuid4()}",
                detection_rule="configuration_change",
                detection_timestamp=datetime.now(timezone.utc),
                is_demo=True,
            )
            session.add(drift)
            await session.commit()
            drift_id = drift.id

        response = await run_action(client, drift_id, RESTORE_CONFIG)
        drift_state = await get_incident(client, drift_id)
        credential_states = [await get_incident(client, i["id"]) for i in credential]

    assert response.status_code == 201 and drift_state["state"] == "RESOLVED"
    assert all(item["state"] == "DETECTED" and item["resolution_timestamp"] is None for item in credential_states)


# --- The shared mapping itself ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("resource_type", RESOURCE_TYPES + [None])
@pytest.mark.parametrize("rule", sorted(DETECTION_RULE_CATEGORY))
def test_every_recommendation_is_an_action_that_recovery_will_accept_or_an_escalation(rule, resource_type):
    metadata = {"cpu_percent": 95.0, "memory_percent": 40.0}
    for sample in (metadata, {"cpu_percent": 50.0, "memory_percent": 40.0}, {}):
        recommendation = recommend_telemetry_action(rule, resource_type, sample)
        if recommendation.action in (ESCALATE, NO_ACTION):
            assert recommendation.rationale
        else:
            assert recommendation.action in ACTION_CATALOG
            assert action_addresses(recommendation.action, DETECTION_RULE_CATEGORY[rule], resource_type)


@pytest.mark.parametrize("category", [CREDENTIAL_ATTACK, NETWORK])
@pytest.mark.parametrize("action_id", sorted(ACTION_CATALOG))
@pytest.mark.parametrize("resource_type", RESOURCE_TYPES)
def test_no_catalog_action_is_considered_to_remediate_credential_or_network_incidents(action_id, category, resource_type):
    assert action_addresses(action_id, category, resource_type) is False


@pytest.mark.parametrize("fault", sorted(OUTAGE_FAULT_CATEGORY))
def test_outage_fault_categories_are_each_remediated_by_some_catalog_action(fault):
    assert any(action_addresses(action, OUTAGE_FAULT_CATEGORY[fault], check_resource=False) for action in ACTION_CATALOG)


@pytest.mark.parametrize(
    ("rule", "resource_type", "metadata", "expected"),
    [
        ("resource_exhaustion", "web_server", {"cpu_percent": 95, "memory_percent": 60}, SCALE),
        ("resource_exhaustion", "web_server", {"cpu_percent": 60, "memory_percent": 90}, SCALE),  # the threshold is inclusive
        ("resource_exhaustion", "web_server", {"cpu_percent": 89.9, "memory_percent": 89.9}, RESTART),
        ("resource_exhaustion", "web_server", {}, RESTART),  # no utilisation evidence: never scale
        ("resource_exhaustion", "web_server", None, RESTART),
        ("resource_exhaustion", "database_server", {"cpu_percent": 99, "memory_percent": 99}, ESCALATE),
        ("resource_exhaustion", None, {"cpu_percent": 99, "memory_percent": 99}, ESCALATE),
        ("dependency_failure", "database_server", None, RESTORE_DEPENDENCY),
        ("dependency_failure", "authentication_service", None, RESTORE_DEPENDENCY),
        ("dependency_failure", "web_server", None, ESCALATE),
        ("configuration_change", "firewall", None, RESTORE_CONFIG),
        ("configuration_change", None, None, RESTORE_CONFIG),
        ("service_availability", "web_server", None, RESTART),
        ("service_availability", "database_server", None, ESCALATE),
        ("repeated_failed_authentication", "authentication_service", None, ESCALATE),
        ("suspicious_login_pattern", "authentication_service", None, ESCALATE),
        ("unusual_network_connection", "firewall", None, ESCALATE),
        ("unusual_network_traffic", "firewall", None, ESCALATE),
        ("some_unknown_rule", "web_server", None, NO_ACTION),
    ],
)
def test_recommendation_rules(rule, resource_type, metadata, expected):
    assert recommend_telemetry_action(rule, resource_type, metadata).action == expected
