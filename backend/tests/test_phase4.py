from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from auth_support import ANONYMOUS_HEADERS



async def setup_incident(client: AsyncClient, scenario: str = "service_unavailable") -> dict:
    service = (
        await client.post(
            "/api/v1/services",
            json={
                "name": f"Phase 4 {uuid4()}",
                "environment": "demo",
                "simulation_status": True,
                "failure_threshold": 1,
            },
        )
    ).json()
    await client.post(f"/api/v1/demo/services/{service['id']}/fault", json={"scenario": scenario})
    await client.post(f"/api/v1/services/{service['id']}/health")
    return next(item for item in (await client.get("/api/v1/incidents")).json() if item["service_id"] == service["id"])


@pytest.mark.asyncio
async def test_approved_recovery_requires_independent_verification():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        incident = await setup_incident(client)
        response = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "restart_demo_application"},
        )
        detail = await client.get(f"/api/v1/incidents/{incident['id']}")
        verification = await client.get(f"/api/v1/incidents/{incident['id']}/verification")
    assert response.status_code == 201
    assert response.json()["status"] == "completed"
    assert verification.json()[0]["outcome"] == "VERIFIED_SUCCESS"
    assert detail.json()["state"] == "RESOLVED"


@pytest.mark.asyncio
async def test_unknown_invalid_and_unauthorized_recovery_are_rejected():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        incident = await setup_incident(client)
        unauthorized = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            headers=ANONYMOUS_HEADERS,  # explicitly anonymous: the default test client is authenticated
            json={"action_id": "restart_demo_application"},
        )
        unknown = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "run_shell_command"},
        )
        invalid = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "scale_demo_application", "parameters": {"instances": 2}, "approved": True},
        )
    assert unauthorized.status_code == 401
    assert unknown.status_code == 409
    assert invalid.status_code == 409


@pytest.mark.asyncio
async def test_high_risk_action_requires_administrator_approval():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        incident = await setup_incident(client)
        rejected = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "reset_demo_environment"},
        )
        approved = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery/approve",
            json={"action_id": "reset_demo_environment"},
        )
        executed = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "reset_demo_environment", "approved": True},
        )
    assert rejected.status_code == 409
    assert rejected.json()["detail"]["code"] == "APPROVAL_REQUIRED"
    assert approved.status_code == 200
    assert executed.status_code == 201


@pytest.mark.asyncio
async def test_policy_rejection_creates_escalation_notification_and_acknowledgement():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        incident = await setup_incident(client)
        await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "restart_demo_application", "parameters": {"unexpected": True}},
        )
        escalations = await client.get(f"/api/v1/incidents/{incident['id']}/escalation")
        notifications = await client.get("/api/v1/notifications")
        acknowledged = await client.post(f"/api/v1/incidents/{incident['id']}/acknowledge")
        timeline = await client.get(f"/api/v1/incidents/{incident['id']}/timeline")
    assert escalations.status_code == 200
    assert escalations.json()[0]["reason"]
    assert any(item["incident_id"] == incident["id"] for item in notifications.json())
    assert acknowledged.status_code == 200
    assert acknowledged.json()["acknowledged"] is True
    assert any(item["event_type"] == "ADMIN_ACKNOWLEDGED" for item in timeline.json())


@pytest.mark.asyncio
async def test_failed_verification_escalates(monkeypatch):
    from app import recovery

    async def leave_fault_in_place(session, service, action_id, parameters):
        return None

    monkeypatch.setattr(recovery, "_execute_demo_action", leave_fault_in_place)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        incident = await setup_incident(client)
        response = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "restart_demo_application"},
        )
        detail = await client.get(f"/api/v1/incidents/{incident['id']}")
        verification = await client.get(f"/api/v1/incidents/{incident['id']}/verification")
    assert response.status_code == 201
    assert verification.json()[0]["outcome"] == "VERIFICATION_FAILED"
    assert detail.json()["state"] == "ESCALATED"
