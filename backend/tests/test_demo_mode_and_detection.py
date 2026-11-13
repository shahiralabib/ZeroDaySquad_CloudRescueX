import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from app.ai import LocalDemoProvider, get_provider
from app.cloud_adapters import CloudLoggingAdapter, CloudMonitoringAdapter, FirestoreAdapter
from app.config import Settings
from app.main import app
from app.threat_intelligence import lookup_indicator



def test_demo_mode_forces_local_provider_and_identifies_sample_indicators():
    settings = Settings(
        operating_mode="DEMO",
        ai_provider="gemini",
        gemini_api_key="not-used",
        gemini_model="not-used",
    )

    assert isinstance(get_provider(settings), LocalDemoProvider)
    assert lookup_indicator("198.51.100.23")["matched"] is True
    assert lookup_indicator("live.example.com")["matched"] is False


@pytest.mark.asyncio
async def test_demo_mode_cloud_adapters_do_not_connect():
    settings = Settings(
        operating_mode="DEMO",
        google_cloud_project="demo-project",
        cloud_monitoring_enabled=True,
        cloud_logging_enabled=True,
        firestore_enabled=True,
    )

    statuses = await asyncio.gather(
        CloudMonitoringAdapter(settings).status(),
        CloudLoggingAdapter(settings).status(),
        FirestoreAdapter(settings).status(),
    )

    assert {status.state for status in statuses} == {"demo_mode"}
    assert all(status.simulated for status in statuses)


@pytest.mark.asyncio
async def test_simulation_events_create_explainable_incidents():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        reset = await client.post("/api/v1/simulation/reset")
        assert reset.status_code == 200
        started = await client.post(
            "/api/v1/simulation/start",
            json={"scenario": "unusual_traffic", "seed": 77, "event_count": 4},
        )
        incidents = await client.get("/api/v1/incidents")

    assert started.status_code == 200
    detected = [item for item in incidents.json() if item["detection_rule"] == "unusual_network_traffic"]
    assert detected
    assert detected[0]["evidence_references"]
    assert detected[0]["priority_score"] > 0
    assert detected[0]["priority_factors"]["blast_radius"] > 0
