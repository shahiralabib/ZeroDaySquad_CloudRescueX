import asyncio
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update

from app.database import RecoveryApproval, session_factory
from app.main import _request_windows, app
from app.recovery import parameters_hash
from auth_support import ANONYMOUS_HEADERS



@pytest.fixture(autouse=True)
def clear_rate_limit_window():
    _request_windows.clear()


async def setup_incident(client: AsyncClient) -> dict:
    service = (
        await client.post(
            "/api/v1/services",
            json={
                "name": f"Approval {uuid4()}",
                "environment": "demo",
                "simulation_status": True,
                "failure_threshold": 1,
            },
        )
    ).json()
    await client.post(
        f"/api/v1/demo/services/{service['id']}/fault",
        json={"scenario": "service_unavailable"},
    )
    await client.post(f"/api/v1/services/{service['id']}/health")
    incidents = (await client.get("/api/v1/incidents")).json()
    return next(item for item in incidents if item["service_id"] == service["id"])


async def approve(client: AsyncClient, incident_id: int, action_id: str, parameters: dict | None = None):
    return await client.post(
        f"/api/v1/incidents/{incident_id}/recovery/approve",
        json={"action_id": action_id, "parameters": parameters or {}},
    )


@pytest.mark.asyncio
async def test_forged_boolean_is_rejected_and_exact_approval_allows_execution():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        incident = await setup_incident(client)
        rejected = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "reset_demo_environment", "approved": True},
        )
        approval = await approve(client, incident["id"], "reset_demo_environment")
        executed = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "reset_demo_environment", "approved": False},
        )
    assert rejected.status_code == 409
    assert rejected.json()["detail"]["code"] == "APPROVAL_REQUIRED"
    assert approval.status_code == 200
    assert executed.status_code == 201


@pytest.mark.asyncio
async def test_approval_cannot_cross_action_or_incident():
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        first = await setup_incident(client)
        second = await setup_incident(client)
        assert (await approve(client, first["id"], "reset_demo_environment")).status_code == 200
        different_action = await client.post(
            f"/api/v1/incidents/{first['id']}/recovery",
            json={"action_id": "restore_known_good_configuration", "approved": True},
        )
        different_incident = await client.post(
            f"/api/v1/incidents/{second['id']}/recovery",
            json={"action_id": "reset_demo_environment", "approved": True},
        )
    assert different_action.json()["detail"]["code"] == "APPROVAL_REQUIRED"
    assert different_incident.json()["detail"]["code"] == "APPROVAL_REQUIRED"


@pytest.mark.asyncio
async def test_different_parameters_invalidate_approval_match():
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        incident = await setup_incident(client)
        approval = await approve(client, incident["id"], "scale_demo_application", {"instances": 1})
        async with session_factory() as session:
            await session.execute(
                update(RecoveryApproval)
                .where(RecoveryApproval.incident_id == incident["id"])
                .values(parameters_hash=parameters_hash({"instances": 2}))
            )
            await session.commit()
        rejected = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "scale_demo_application", "parameters": {"instances": 1}, "approved": True},
        )
    assert approval.status_code == 200
    assert rejected.status_code == 409
    assert rejected.json()["detail"]["code"] == "APPROVAL_REQUIRED"


@pytest.mark.asyncio
async def test_expired_and_revoked_approvals_are_rejected():
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        incident = await setup_incident(client)
        assert (await approve(client, incident["id"], "reset_demo_environment")).status_code == 200
        async with session_factory() as session:
            approval = await session.scalar(
                select(RecoveryApproval)
                .where(RecoveryApproval.incident_id == incident["id"])
                .order_by(RecoveryApproval.created_at.desc())
            )
            approval.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            await session.commit()
        expired = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "reset_demo_environment"},
        )
        incident = await setup_incident(client)
        assert (await approve(client, incident["id"], "reset_demo_environment")).status_code == 200
        async with session_factory() as session:
            approval = await session.scalar(
                select(RecoveryApproval)
                .where(RecoveryApproval.incident_id == incident["id"])
                .order_by(RecoveryApproval.created_at.desc())
            )
            approval.revoked = True
            await session.commit()
        revoked = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "reset_demo_environment"},
        )
    assert expired.json()["detail"]["code"] == "APPROVAL_REQUIRED"
    assert revoked.json()["detail"]["code"] == "APPROVAL_REQUIRED"


@pytest.mark.asyncio
async def test_consumed_approval_cannot_be_reused_or_retry_authorized():
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        incident = await setup_incident(client)
        assert (await approve(client, incident["id"], "reset_demo_environment")).status_code == 200
        executed = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "reset_demo_environment"},
        )
        async with session_factory() as session:
            approval = await session.scalar(
                select(RecoveryApproval)
                .where(RecoveryApproval.incident_id == incident["id"])
                .order_by(RecoveryApproval.created_at.desc())
            )
            consumed_at = approval.consumed_at
        reused = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery/retry",
            json={"action_id": "reset_demo_environment"},
        )
    assert executed.status_code == 201
    assert consumed_at is not None
    assert reused.status_code == 409


@pytest.mark.asyncio
async def test_retry_without_approval_is_rejected():
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        incident = await setup_incident(client)
        response = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery/retry",
            json={"action_id": "reset_demo_environment"},
        )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "APPROVAL_REQUIRED"


@pytest.mark.asyncio
async def test_unauthenticated_approval_and_execution_are_rejected():
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        approval = await client.post(
            "/api/v1/incidents/1/recovery/approve",
            headers=ANONYMOUS_HEADERS,  # explicitly anonymous: the default test client is authenticated
            json={"action_id": "reset_demo_environment"},
        )
        execution = await client.post(
            "/api/v1/incidents/1/recovery",
            headers=ANONYMOUS_HEADERS,
            json={"action_id": "reset_demo_environment", "approved": True},
        )
    assert approval.status_code == 401
    assert execution.status_code == 401


@pytest.mark.asyncio
async def test_concurrent_requests_consume_one_approval():
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        incident = await setup_incident(client)
        assert (await approve(client, incident["id"], "scale_demo_application", {"instances": 1})).status_code == 200

        async def execute():
            return await client.post(
                f"/api/v1/incidents/{incident['id']}/recovery",
                json={"action_id": "scale_demo_application", "parameters": {"instances": 1}, "approved": True},
            )

        results = await asyncio.gather(execute(), execute())
    assert sorted(result.status_code for result in results) == [201, 409]


@pytest.mark.asyncio
async def test_low_risk_recovery_does_not_require_approval():
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        incident = await setup_incident(client)
        response = await client.post(
            f"/api/v1/incidents/{incident['id']}/recovery",
            json={"action_id": "restart_demo_application", "approved": False},
        )
    assert response.status_code == 201
