import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from auth_support import ANONYMOUS_HEADERS



async def simulation_client():
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    )


@pytest.mark.asyncio
async def test_simulation_resources_have_relationships_and_persisted_metadata():
    async with await simulation_client() as client:
        await client.post("/api/v1/simulation/reset")
        response = await client.get("/api/v1/simulation/resources")
        status_response = await client.get("/api/v1/simulation/status")

    assert response.status_code == 200
    resources = response.json()
    assert {resource["resource_type"] for resource in resources} == {
        "web_server",
        "database_server",
        "authentication_service",
        "firewall",
        "vpn_gateway",
    }
    assert all(resource["simulated"] is True for resource in resources)
    assert all(resource["metadata"]["source"] == "local_simulation" for resource in resources)
    assert any(resource["parent_resource_id"] is not None for resource in resources)
    assert status_response.json()["status"] == "stopped"


@pytest.mark.asyncio
async def test_simulation_start_filters_and_deterministically_replays_events():
    async with await simulation_client() as client:
        await client.post("/api/v1/simulation/reset")
        unauthorized = await client.post(
            "/api/v1/simulation/start",
            headers=ANONYMOUS_HEADERS,  # explicitly anonymous: the default test client is authenticated
            json={"scenario": "authentication_attack", "seed": 42, "event_count": 6},
        )
        started = await client.post(
            "/api/v1/simulation/start",
            json={"scenario": "authentication_attack", "seed": 42, "event_count": 6},
        )
        events = await client.get(
            "/api/v1/simulation/events",
            params={"category": "authentication", "severity": "high", "limit": 2},
        )
        first_run = await client.get("/api/v1/simulation/events", params={"limit": 100})
        reset = await client.post("/api/v1/simulation/reset")
        replay = await client.post(
            "/api/v1/simulation/start",
            json={"scenario": "authentication_attack", "seed": 42, "event_count": 6},
        )
        second_run = await client.get("/api/v1/simulation/events", params={"limit": 100})

    assert unauthorized.status_code == 401
    assert started.status_code == 200
    assert started.json()["scenario"] == "authentication_attack"
    assert started.json()["tick_count"] == 1
    assert events.status_code == 200
    assert len(events.json()) == 2
    assert all(item["category"] == "authentication" for item in events.json())
    assert all(item["severity"] == "high" for item in events.json())
    assert reset.status_code == 200
    assert replay.status_code == 200
    assert [item["event_type"] for item in first_run.json()] == [
        item["event_type"] for item in second_run.json()
    ]
    assert [item["metadata"] for item in first_run.json()] == [
        item["metadata"] for item in second_run.json()
    ]
    assert all(item["source"] == "local_simulation" for item in second_run.json())


@pytest.mark.asyncio
async def test_simulation_validation_and_pagination_errors():
    async with await simulation_client() as client:
        invalid_scenario = await client.post(
            "/api/v1/simulation/start",
            json={"scenario": "unknown"},
        )
        invalid_window = await client.get(
            "/api/v1/simulation/events",
            params={"start_time": "2026-01-02T00:00:00Z", "end_time": "2026-01-01T00:00:00Z"},
        )
        oversized_page = await client.get("/api/v1/simulation/events", params={"limit": 201})

    assert invalid_scenario.status_code == 422
    assert invalid_window.status_code == 422
    assert oversized_page.status_code == 422
