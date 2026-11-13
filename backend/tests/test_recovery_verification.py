"""Recovery must fix the fault it targets, and verification must never pass for an incorrect or ineffective action."""
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import Incident, RecoveryApproval, Service, session_factory
from app.main import _request_windows, app


@pytest.fixture(autouse=True)
def clear_rate_limit_window():
    _request_windows.clear()


def new_client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def run_scenario(client: AsyncClient, scenario: str) -> list[dict]:
    """Reset, start a run, and return the incidents it created."""
    assert (await client.post("/api/v1/simulation/reset")).status_code == 200
    before = {item["id"] for item in (await client.get("/api/v1/incidents")).json()}
    started = await client.post(
        "/api/v1/simulation/start", json={"scenario": scenario, "seed": 42, "event_count": 10}
    )
    assert started.status_code == 200
    return [item for item in (await client.get("/api/v1/incidents")).json() if item["id"] not in before]


def by_rule(incidents: list[dict], rule: str) -> dict:
    return next(item for item in incidents if item["detection_rule"] == rule)


async def resource_statuses(client: AsyncClient) -> dict[str, str]:
    return {item["resource_key"]: item["status"] for item in (await client.get("/api/v1/simulation/resources")).json()}


async def execute(client: AsyncClient, incident_id: int, action_id: str):
    return await client.post(f"/api/v1/incidents/{incident_id}/recovery", json={"action_id": action_id})


async def approve(client: AsyncClient, incident_id: int, action_id: str):
    return await client.post(
        f"/api/v1/incidents/{incident_id}/recovery/approve", json={"action_id": action_id}
    )


async def outcome(client: AsyncClient, incident_id: int) -> tuple[dict, dict]:
    incident = (await client.get(f"/api/v1/incidents/{incident_id}")).json()
    verifications = (await client.get(f"/api/v1/incidents/{incident_id}/verification")).json()
    # The endpoint orders by a one-second timestamp, so pick the newest attempt by id instead of by list position.
    return incident, max(verifications, key=lambda item: item["id"])


def checks_of(verification: dict) -> list[dict]:
    evidence = verification["evidence"]
    return evidence["value"] if isinstance(evidence, dict) else evidence


async def create_outage(client: AsyncClient, scenario: str) -> dict:
    service = (
        await client.post(
            "/api/v1/services",
            json={"name": f"Verify {uuid4()}", "environment": "demo", "simulation_status": True, "failure_threshold": 1},
        )
    ).json()
    await client.post(f"/api/v1/demo/services/{service['id']}/fault", json={"scenario": scenario})
    incident = next(i for i in (await client.get("/api/v1/incidents")).json() if i["service_id"] == service["id"])
    return {"service": service, "incident": incident}


# --- The reported failure -----------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_restarting_the_application_does_not_verify_an_authentication_attack():
    """Reproduces the reported bug: restart_demo_application used to give VERIFIED_SUCCESS with sim-auth-01 still degraded."""
    async with new_client() as client:
        incident = by_rule(await run_scenario(client, "authentication_attack"), "repeated_failed_authentication")
        investigation = (await client.post(f"/api/v1/incidents/{incident['id']}/investigations")).json()
        assert investigation["result"]["recommended_action"] == "escalate_to_administrator"  # no action can contain a credential attack
        assert (await resource_statuses(client))["sim-auth-01"] == "degraded"

        # The investigation escalated the incident, so a plain execute is refused outright...
        refused = await execute(client, incident["id"], "restart_demo_application")
        # ...and an administrator-authorised retry of the wrong action runs but cannot be verified.
        response = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery/retry",
            json={"action_id": "restart_demo_application", "approved": True},
        )
        refreshed, verification = await outcome(client, incident["id"])
        resources = await resource_statuses(client)

    assert refused.status_code == 409 and refused.json()["detail"]["code"] == "INVALID_INCIDENT_STATE"
    assert response.status_code == 201 and response.json()["status"] == "completed"  # the action ran...
    assert verification["outcome"] == "VERIFICATION_FAILED"  # ...but it did not fix the fault
    assert verification["successful_checks"] == 0
    assert refreshed["verification_outcome"] == "VERIFICATION_FAILED"
    assert refreshed["state"] == "ESCALATED" and refreshed["resolution_timestamp"] is None
    assert resources["sim-auth-01"] == "degraded"
    check = checks_of(verification)[0]
    assert check["action_addresses_fault"] is False and check["fault_category"] == "credential_attack"
    assert check["affected_resource"] == "sim-auth-01" and check["affected_resource_healthy"] is False


@pytest.mark.asyncio
async def test_the_correct_action_still_resolves_after_a_failed_attempt_and_still_needs_one_time_approval():
    async with new_client() as client:
        drifts = await run_scenario(client, "configuration_drift")  # degrades all five assets with configuration changes
        incident = next(i for i in drifts if i["diagnostic_evidence"]["resource_key"] == "sim-firewall-01")
        await execute(client, incident["id"], "restart_demo_application")  # wrong action first: it cannot act on a firewall

        # The failed verification escalated the incident, so nothing can run until an administrator approves again.
        blocked = await execute(client, incident["id"], "restore_known_good_configuration")
        assert blocked.status_code == 409 and blocked.json()["detail"]["code"] == "INVALID_INCIDENT_STATE"
        assert (await approve(client, incident["id"], "restore_known_good_configuration")).status_code == 200
        fixed = await execute(client, incident["id"], "restore_known_good_configuration")
        refreshed, verification = await outcome(client, incident["id"])
        resources = await resource_statuses(client)
        replay = await execute(client, incident["id"], "restore_known_good_configuration")

    assert fixed.status_code == 201
    assert verification["outcome"] == "VERIFIED_SUCCESS" and verification["successful_checks"] == 2
    assert refreshed["state"] == "RESOLVED" and refreshed["resolution_timestamp"]
    assert resources["sim-firewall-01"] == "healthy"
    assert {key: status for key, status in resources.items() if key != "sim-firewall-01"} == {
        "sim-vpn-01": "degraded", "sim-web-01": "degraded", "sim-auth-01": "degraded", "sim-db-01": "degraded",
    }  # only the incident's own asset was restored
    check = checks_of(verification)[0]
    assert check["action_addresses_fault"] is True and check["affected_resource_healthy"] is True
    assert replay.status_code == 409  # the approval was consumed and the action already ran

    async with session_factory() as session:
        approvals = (
            await session.scalars(
                select(RecoveryApproval).where(
                    RecoveryApproval.incident_id == incident["id"],
                    RecoveryApproval.action_id == "restore_known_good_configuration",
                )
            )
        ).all()
    assert len(approvals) == 1 and approvals[0].consumed_at is not None


@pytest.mark.asyncio
async def test_a_correct_action_heals_only_the_affected_resource():
    async with new_client() as client:
        incidents = await run_scenario(client, "resource_pressure")  # degrades sim-web-01 and sim-db-01
        web = next(i for i in incidents if i["diagnostic_evidence"]["resource_key"] == "sim-web-01")
        database = next(i for i in incidents if i["diagnostic_evidence"]["resource_key"] == "sim-db-01")
        before = await resource_statuses(client)
        assert before["sim-web-01"] == "degraded" and before["sim-db-01"] == "degraded"

        response = await execute(client, web["id"], "restart_demo_application")  # low risk, addresses resource exhaustion
        resources = await resource_statuses(client)
        web_after, web_verification = await outcome(client, web["id"])
        database_after = (await client.get(f"/api/v1/incidents/{database['id']}")).json()

    assert response.status_code == 201
    assert web_verification["outcome"] == "VERIFIED_SUCCESS" and web_after["state"] == "RESOLVED"
    assert resources["sim-web-01"] == "healthy"
    assert resources["sim-db-01"] == "degraded"  # unrelated resource is not marked healthy
    assert database_after["state"] == "DETECTED"


@pytest.mark.asyncio
async def test_an_inapplicable_action_cannot_verify_even_if_the_resource_looks_healthy():
    async with new_client() as client:
        incident = by_rule(await run_scenario(client, "authentication_attack"), "repeated_failed_authentication")
        assert (await client.post("/api/v1/simulation/reset")).status_code == 200  # resources healthy again
        assert (await resource_statuses(client))["sim-auth-01"] == "healthy"

        await execute(client, incident["id"], "restart_demo_application")
        refreshed, verification = await outcome(client, incident["id"])

    assert verification["outcome"] == "VERIFICATION_FAILED"
    assert checks_of(verification)[0]["action_addresses_fault"] is False
    assert refreshed["state"] == "ESCALATED"


@pytest.mark.asyncio
async def test_verification_fails_when_the_affected_resource_cannot_be_determined():
    async with new_client() as client:
        async with session_factory() as session:
            service = await session.scalar(select(Service).where(Service.name == "Checkout API"))
            legacy = Incident(
                service_id=service.id,
                incident_type="configuration_change",
                severity="medium",
                state="INVESTIGATING",
                summary="Legacy telemetry incident without a recorded asset",
                diagnostic_evidence=json.dumps({"event_id": str(uuid4()), "metadata": {"setting": "max_connections"}}),
                deduplication_key=f"legacy-{uuid4()}",
                detection_rule="configuration_change",
                detection_timestamp=datetime.now(timezone.utc),
                is_demo=True,
            )
            session.add(legacy)
            await session.commit()
            legacy_id = legacy.id
        await approve(client, legacy_id, "restore_known_good_configuration")
        await execute(client, legacy_id, "restore_known_good_configuration")
        refreshed, verification = await outcome(client, legacy_id)

    assert verification["outcome"] == "VERIFICATION_FAILED"
    assert checks_of(verification)[0]["affected_resource"] is None
    assert refreshed["state"] != "RESOLVED"


# --- Outage (health-check) incidents ----------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fault", "wrong_action"),
    [
        ("service_unavailable", "restore_demo_dependency"),
        ("dependency_unavailable", "restart_demo_application"),
        ("configuration_failure", "restart_demo_application"),
        ("configuration_failure", "restore_demo_dependency"),
    ],
)
async def test_an_action_that_does_not_address_the_outage_fault_leaves_it_unresolved(fault, wrong_action):
    async with new_client() as client:
        created = await create_outage(client, fault)
        incident_id, service_id = created["incident"]["id"], created["service"]["id"]

        response = await execute(client, incident_id, wrong_action)
        refreshed, verification = await outcome(client, incident_id)
        service = (await client.get(f"/api/v1/services/{service_id}")).json()

    assert response.status_code == 201
    assert verification["outcome"] == "VERIFICATION_FAILED"
    assert refreshed["state"] == "ESCALATED" and refreshed["resolution_timestamp"] is None
    assert service["status"] == "unhealthy"  # the fault was not cleared


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fault", "right_action"),
    [("service_unavailable", "restart_demo_application"), ("dependency_unavailable", "restore_demo_dependency")],
)
async def test_the_action_that_addresses_the_outage_fault_resolves_it(fault, right_action):
    async with new_client() as client:
        created = await create_outage(client, fault)
        incident_id, service_id = created["incident"]["id"], created["service"]["id"]

        response = await execute(client, incident_id, right_action)
        refreshed, verification = await outcome(client, incident_id)
        service = (await client.get(f"/api/v1/services/{service_id}")).json()

    assert response.status_code == 201
    assert verification["outcome"] == "VERIFIED_SUCCESS" and verification["successful_checks"] == 2
    assert refreshed["state"] == "RESOLVED"
    assert service["status"] == "healthy"


@pytest.mark.asyncio
async def test_recovering_a_telemetry_incident_does_not_clear_an_unrelated_service_fault():
    async with new_client() as client:
        incident = by_rule(await run_scenario(client, "configuration_drift"), "configuration_change")
        outage = await create_outage(client, "service_unavailable")  # unrelated service with its own fault
        await approve(client, incident["id"], "restore_known_good_configuration")
        await execute(client, incident["id"], "restore_known_good_configuration")
        service = (await client.get(f"/api/v1/services/{outage['service']['id']}")).json()
        outage_incident = (await client.get(f"/api/v1/incidents/{outage['incident']['id']}")).json()

    assert service["status"] == "unhealthy"
    assert outage_incident["state"] == "DETECTED"
