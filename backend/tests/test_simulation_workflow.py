"""Simulation workflow: asset-to-service mapping, per-run incident identity, and immediate fault detection."""
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import Incident, TelemetryEvent, session_factory
from app.main import _request_windows, app
from app.simulation import RESOURCE_SERVICE_NAMES, detect_telemetry

ADMIN = {"X-Demo-Admin-Token": "local-demo-admin"}


@pytest.fixture(autouse=True)
def clear_rate_limit_window():
    _request_windows.clear()


def new_client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def incidents_by_id(client: AsyncClient) -> dict[int, dict]:
    return {item["id"]: item for item in (await client.get("/api/v1/incidents")).json()}


async def run_scenario(client: AsyncClient, scenario: str, seed: int = 42, event_count: int = 10) -> dict[int, dict]:
    """Reset, start a run, and return only the incidents that run created."""
    assert (await client.post("/api/v1/simulation/reset", headers=ADMIN)).status_code == 200
    before = await incidents_by_id(client)
    started = await client.post(
        "/api/v1/simulation/start",
        headers=ADMIN,
        json={"scenario": scenario, "seed": seed, "event_count": event_count},
    )
    assert started.status_code == 200
    after = await incidents_by_id(client)
    return {key: value for key, value in after.items() if key not in before}


async def create_demo_service(client: AsyncClient, threshold: int = 2) -> dict:
    response = await client.post(
        "/api/v1/services",
        json={"name": f"Workflow {uuid4()}", "environment": "demo", "simulation_status": True, "failure_threshold": threshold},
    )
    assert response.status_code == 201
    return response.json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scenario", "expected"),
    [
        ("authentication_attack", {"sim-auth-01": "Checkout API"}),
        ("network_disruption", {"sim-firewall-01": "Customer Portal", "sim-vpn-01": "Payments Worker"}),
        ("resource_pressure", {"sim-web-01": "Customer Portal", "sim-db-01": "Payments Worker"}),
        ("dependency_failure", {"sim-db-01": "Payments Worker"}),
    ],
)
async def test_telemetry_incidents_target_the_affected_service_and_keep_resource_key(scenario, expected):
    async with new_client() as client:
        created = await run_scenario(client, scenario)

    assert created
    assert {item["diagnostic_evidence"]["resource_key"]: item["service_name"] for item in created.values()} == expected
    for item in created.values():
        resource_key = item["diagnostic_evidence"]["resource_key"]
        assert RESOURCE_SERVICE_NAMES[resource_key] == item["service_name"]
        assert f"resource:{resource_key}" in item["evidence_references"]
        assert any(reference.startswith("telemetry:") for reference in item["evidence_references"])


@pytest.mark.asyncio
async def test_unmapped_asset_falls_back_to_a_demo_service():
    from app import simulation

    original = dict(simulation.RESOURCE_SERVICE_NAMES)
    simulation.RESOURCE_SERVICE_NAMES.clear()
    try:
        async with new_client() as client:
            created = await run_scenario(client, "authentication_attack")
    finally:
        simulation.RESOURCE_SERVICE_NAMES.update(original)

    assert created
    assert all(item["service_name"] for item in created.values())


@pytest.mark.asyncio
async def test_same_scenario_and_seed_after_reset_creates_fresh_incidents_and_keeps_history():
    async with new_client() as client:
        first = await run_scenario(client, "authentication_attack", seed=42)
        second = await run_scenario(client, "authentication_attack", seed=42)
        everything = await incidents_by_id(client)

    assert first and second
    assert set(first).isdisjoint(second)
    assert len(first) == len(second)
    # Historical incidents from the first run are preserved.
    assert set(first) <= set(everything)
    assert {item["detection_rule"] for item in first.values()} == {item["detection_rule"] for item in second.values()}


@pytest.mark.asyncio
async def test_one_run_does_not_create_duplicate_incidents():
    async with new_client() as client:
        created = await run_scenario(client, "authentication_attack")
    rules_and_assets = [(item["detection_rule"], item["diagnostic_evidence"]["resource_key"]) for item in created.values()]
    assert len(rules_and_assets) == len(set(rules_and_assets))

    # Re-running detection over the same run's telemetry must not add anything.
    async with session_factory() as session:
        records = list((await session.scalars(select(TelemetryEvent))).all())
        assert records
        assert await detect_telemetry(session, records) == []
        await session.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize("threshold", [1, 2, 3])
async def test_fault_injection_detects_the_failure_immediately(threshold):
    async with new_client() as client:
        service = await create_demo_service(client, threshold=threshold)
        injected = await client.post(
            f"/api/v1/demo/services/{service['id']}/fault", headers=ADMIN, json={"scenario": "service_unavailable"}
        )
        # No separate health-check call: detection must already have happened.
        incidents = [item for item in (await client.get("/api/v1/incidents")).json() if item["service_id"] == service["id"]]
        refreshed = (await client.get(f"/api/v1/services/{service['id']}")).json()

    assert injected.status_code == 200
    assert injected.json()["health_checks_run"] == threshold
    assert len(incidents) == 1
    assert incidents[0]["state"] == "DETECTED"
    assert incidents[0]["incident_type"] == "service_unavailable"
    assert refreshed["status"] == "unhealthy"
    assert refreshed["consecutive_failure_count"] == threshold


@pytest.mark.asyncio
async def test_injecting_healthy_does_not_run_health_checks():
    async with new_client() as client:
        service = await create_demo_service(client)
        response = await client.post(
            f"/api/v1/demo/services/{service['id']}/fault", headers=ADMIN, json={"scenario": "healthy"}
        )
        incidents = [item for item in (await client.get("/api/v1/incidents")).json() if item["service_id"] == service["id"]]

    assert response.status_code == 200
    assert response.json()["health_checks_run"] == 0
    assert incidents == []


@pytest.mark.asyncio
async def test_telemetry_incident_neither_blocks_outage_detection_nor_is_auto_resolved():
    async with new_client() as client:
        service = await create_demo_service(client)
        async with session_factory() as session:
            telemetry_incident = Incident(
                service_id=service["id"],
                severity="high",
                state="DETECTED",
                summary="Repeated authentication failure from an unusual source",
                deduplication_key=f"test-telemetry-{uuid4()}",
                detection_rule="repeated_failed_authentication",
                detection_timestamp=datetime.now(timezone.utc),
                is_demo=True,
            )
            session.add(telemetry_incident)
            await session.commit()
            telemetry_id = telemetry_incident.id

        await client.post(f"/api/v1/demo/services/{service['id']}/fault", headers=ADMIN, json={"scenario": "service_unavailable"})
        on_service = [item for item in (await client.get("/api/v1/incidents")).json() if item["service_id"] == service["id"]]
        outage = next(item for item in on_service if item["detection_rule"] == "health_check_failure")

        await client.post(f"/api/v1/demo/services/{service['id']}/reset", headers=ADMIN)
        recovered = await client.post(f"/api/v1/services/{service['id']}/health")
        outage_after = (await client.get(f"/api/v1/incidents/{outage['id']}")).json()
        telemetry_after = (await client.get(f"/api/v1/incidents/{telemetry_id}")).json()

    assert len(on_service) == 2
    assert recovered.json()["status"] == "healthy"
    assert outage_after["state"] == "RESOLVED"
    assert telemetry_after["state"] == "DETECTED"
