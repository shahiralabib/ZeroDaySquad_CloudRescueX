from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def create_service(client: AsyncClient, *, simulation_status: bool = True, threshold: int = 2) -> dict:
    response = await client.post(
        "/api/v1/services",
        json={
            "name": f"Phase 2 {uuid4()}",
            "description": "Test service",
            "environment": "demo" if simulation_status else "production",
            "failure_threshold": threshold,
            "monitoring_interval_seconds": 5,
            "simulation_status": simulation_status,
        },
    )
    assert response.status_code == 201
    return response.json()


@pytest.mark.asyncio
async def test_successful_health_check_is_persisted(client: AsyncClient):
    async with client:
        service = await create_service(client)
        response = await client.post(f"/api/v1/services/{service['id']}/health")
        history = await client.get(f"/api/v1/services/{service['id']}/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["simulated"] is True
    assert history.status_code == 200
    assert len(history.json()) >= 1


@pytest.mark.asyncio
async def test_failure_threshold_creates_one_incident_and_recovery_resolves_it(client: AsyncClient):
    async with client:
        service = await create_service(client, threshold=2)
        fault = await client.post(
            f"/api/v1/demo/services/{service['id']}/fault",
            headers={"X-Demo-Admin-Token": "local-demo-admin"},
            json={"scenario": "service_unavailable"},
        )
        assert fault.status_code == 200
        first = await client.post(f"/api/v1/services/{service['id']}/health")
        second = await client.post(f"/api/v1/services/{service['id']}/health")
        third = await client.post(f"/api/v1/services/{service['id']}/health")
        incidents = await client.get("/api/v1/incidents")
        matching = [incident for incident in incidents.json() if incident["service_id"] == service["id"]]
        reset = await client.post(
            f"/api/v1/demo/services/{service['id']}/reset",
            headers={"X-Demo-Admin-Token": "local-demo-admin"},
        )
        recovered = await client.post(f"/api/v1/services/{service['id']}/health")
        timeline = await client.get(f"/api/v1/incidents/{matching[0]['id']}/timeline")
    assert first.json()["status"] == "unhealthy"
    assert second.json()["status"] == "unhealthy"
    assert third.status_code == 200
    assert len(matching) == 1
    assert matching[0]["state"] == "DETECTED"
    assert reset.status_code == 200
    assert recovered.json()["status"] == "healthy"
    assert any(event["event_type"] == "DETECTION" for event in timeline.json())
    assert any(event["event_type"] == "RESOLUTION" for event in timeline.json())


@pytest.mark.asyncio
async def test_incident_state_transitions_reject_arbitrary_changes(client: AsyncClient):
    async with client:
        service = await create_service(client, threshold=1)
        await client.post(
            f"/api/v1/demo/services/{service['id']}/fault",
            headers={"X-Demo-Admin-Token": "local-demo-admin"},
            json={"scenario": "configuration_failure"},
        )
        await client.post(f"/api/v1/services/{service['id']}/health")
        incident = next(item for item in (await client.get("/api/v1/incidents")).json() if item["service_id"] == service["id"])
        invalid = await client.patch(
            f"/api/v1/incidents/{incident['id']}/state",
            json={"target_state": "RESOLVED"},
        )
        valid = await client.patch(
            f"/api/v1/incidents/{incident['id']}/state",
            json={"target_state": "INVESTIGATING", "description": "Operator began investigation"},
        )
    assert invalid.status_code == 409
    assert valid.status_code == 200
    assert valid.json()["state"] == "INVESTIGATING"


@pytest.mark.asyncio
async def test_demo_fault_operations_require_authorization_and_isolate_non_demo_services(client: AsyncClient):
    async with client:
        demo_service = await create_service(client)
        unauthorized = await client.post(
            f"/api/v1/demo/services/{demo_service['id']}/fault",
            json={"scenario": "dependency_unavailable"},
        )
        production_service = await create_service(client, simulation_status=False)
        forbidden = await client.post(
            f"/api/v1/demo/services/{production_service['id']}/fault",
            headers={"X-Demo-Admin-Token": "local-demo-admin"},
            json={"scenario": "dependency_unavailable"},
        )
        scenarios = await client.get("/api/v1/demo/scenarios")
    assert unauthorized.status_code == 401
    assert forbidden.status_code == 403
    assert scenarios.json()["simulated"] is True
    assert "dependency_unavailable" in scenarios.json()["scenarios"]


@pytest.mark.asyncio
async def test_service_management_and_dashboard_stats(client: AsyncClient):
    async with client:
        service = await create_service(client)
        detail = await client.get(f"/api/v1/services/{service['id']}")
        updated = await client.patch(
            f"/api/v1/services/{service['id']}",
            json={"description": "Updated description", "failure_threshold": 3},
        )
        stats = await client.get("/api/v1/dashboard/stats")
    assert detail.status_code == 200
    assert updated.json()["description"] == "Updated description"
    assert updated.json()["failure_threshold"] == 3
    assert stats.status_code == 200
    assert "failed_checks_last_hour" in stats.json()
