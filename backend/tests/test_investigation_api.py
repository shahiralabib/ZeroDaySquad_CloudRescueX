import pytest
from httpx import ASGITransport, AsyncClient
from uuid import uuid4

from app.main import app


@pytest.mark.asyncio
async def test_local_investigation_is_persisted_and_labeled():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        service = (
            await client.post(
                "/api/v1/services",
                json={
                    "name": f"Investigation API Service {uuid4()}",
                    "environment": "demo",
                    "simulation_status": True,
                    "failure_threshold": 1,
                },
            )
        ).json()
        await client.post(
            f"/api/v1/demo/services/{service['id']}/fault",
            json={"scenario": "dependency_unavailable"},
        )
        await client.post(f"/api/v1/services/{service['id']}/health")
        incidents = (await client.get("/api/v1/incidents")).json()
        incident = next(item for item in incidents if item["service_id"] == service["id"])
        response = await client.post(f"/api/v1/incidents/{incident['id']}/investigations")
        saved = await client.get(f"/api/v1/incidents/{incident['id']}/investigations")
    assert response.status_code == 201
    assert response.json()["provider"] == "local_deterministic"
    assert response.json()["simulated"] is True
    assert response.json()["result"]["evidence_references"]
    assert saved.status_code == 200
    assert len(saved.json()) == 1


@pytest.mark.asyncio
async def test_ai_status_does_not_claim_gemini_without_credentials():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/ai/status")
    assert response.status_code == 200
    assert response.json()["provider"] == "local_deterministic"
    assert response.json()["simulated"] is True
