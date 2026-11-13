"""Telemetry evidence and offline threat intelligence flow from detection into the AI investigation."""
import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.ai import InvestigationInput, LocalDemoProvider
from app.config import get_settings
from app.database import Incident, Service, session_factory
from app.main import _request_windows, app
from app.simulation import DEMO_BRUTE_FORCE_SOURCE, DEMO_UNUSUAL_TRAFFIC_SOURCE
from sqlalchemy import select

ADMIN = {"X-Demo-Admin-Token": "local-demo-admin"}
ALL_ACTIONS = [
    "restart_demo_application",
    "restore_known_good_configuration",
    "restore_demo_dependency",
    "scale_demo_application",
    "reset_demo_environment",
]


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


def by_rule(incidents: list[dict], rule: str) -> dict:
    return next(item for item in incidents if item["detection_rule"] == rule)


def telemetry_input(**overrides) -> InvestigationInput:
    payload = {
        "service_metadata": {"name": "Checkout API"},
        "health_checks": [],
        "available_recovery_actions": ALL_ACTIONS,
        "telemetry_evidence": [
            {
                "evidence_id": "telemetry:evt-1",
                "resource_key": "sim-auth-01",
                "rule": "repeated_failed_authentication",
                "event_type": "authentication_failure",
                "severity": "high",
                "summary": "Repeated authentication failure from an unusual source",
                "metadata": {"source_ip": "198.51.100.23", "username": "synthetic-user-1", "attempt": 3},
            }
        ],
    }
    payload.update(overrides)
    return InvestigationInput.model_validate(payload)


SUSPICIOUS_INTEL = {
    "evidence_id": "threat_intel:198.51.100.23",
    "indicator": "198.51.100.23",
    "matched": True,
    "reputation": "suspicious_sample",
    "confidence": 0.91,
    "mitre_attack_techniques": ["T1110"],
    "description": "Reserved documentation address used to model repeated authentication failures.",
}


# --- Detection -------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_detection_attaches_threat_intelligence_and_explainable_priority_factors():
    async with new_client() as client:
        incidents = await run_scenario(client, "authentication_attack")

    brute_force = by_rule(incidents, "repeated_failed_authentication")
    finding = brute_force["diagnostic_evidence"]["threat_intelligence"]
    assert finding["indicator"] == DEMO_BRUTE_FORCE_SOURCE
    assert finding["matched"] is True and finding["reputation"] == "suspicious_sample"
    assert finding["mitre_attack_techniques"] == ["T1110"]
    assert finding["observable"] == "source_ip" and finding["source"] == "local_demo_dataset"
    assert f"threat_intel:{DEMO_BRUTE_FORCE_SOURCE}" in brute_force["evidence_references"]
    assert brute_force["priority_factors"]["threat_intelligence"] == 91
    # The score is the documented mean of the visible factors.
    factors = brute_force["priority_factors"]
    assert brute_force["priority_score"] == round(sum(factors.values()) / len(factors), 2)

    # The varied suspicious-login source is only in the reserved documentation range: a weaker match.
    login = by_rule(incidents, "suspicious_login_pattern")
    assert login["diagnostic_evidence"]["threat_intelligence"]["reputation"] == "reserved_sample_range"
    assert login["priority_factors"]["threat_intelligence"] == 55


@pytest.mark.asyncio
async def test_unusual_traffic_matches_its_sample_indicator_and_network_events_without_an_ip_are_unenriched():
    async with new_client() as client:
        traffic = await run_scenario(client, "unusual_traffic")
        network = await run_scenario(client, "network_disruption")

    finding = by_rule(traffic, "unusual_network_traffic")["diagnostic_evidence"]["threat_intelligence"]
    assert finding["indicator"] == DEMO_UNUSUAL_TRAFFIC_SOURCE and finding["mitre_attack_techniques"] == ["T1071.001"]
    for item in network:
        assert "threat_intelligence" not in item["diagnostic_evidence"]
        assert "threat_intelligence" not in item["priority_factors"]
        assert not any(reference.startswith("threat_intel:") for reference in item["evidence_references"])


# --- Investigation through the API --------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_investigation_of_a_telemetry_incident_uses_its_telemetry_and_threat_intelligence():
    async with new_client() as client:
        incidents = await run_scenario(client, "authentication_attack")
        incident = by_rule(incidents, "repeated_failed_authentication")
        response = await client.post(f"/api/v1/incidents/{incident['id']}/investigations")
        refreshed = (await client.get(f"/api/v1/incidents/{incident['id']}")).json()

    assert response.status_code == 201
    body = response.json()
    result = body["result"]
    # Meaningful result instead of "insufficient evidence": completed, not escalated.
    assert body["status"] == "completed" and body["provider"] == "local_deterministic" and body["simulated"] is True
    assert body["confidence"] >= get_settings().ai_confidence_threshold
    assert "brute-force" in result["probable_root_cause"]
    assert "198.51.100.23" in result["root_cause_explanation"] and "T1110" in result["root_cause_explanation"]
    # Restoring configuration does not stop a credential attack, so the recommendation is manual containment.
    assert result["recommended_action"] == "escalate_to_administrator"
    assert "account or session containment" in result["reason_for_recommendation"]
    assert result["human_intervention_recommended"] is True
    refs = result["evidence_references"]
    assert refs[0].startswith("telemetry:") and "resource:sim-auth-01" in refs
    assert f"threat_intel:{DEMO_BRUTE_FORCE_SOURCE}" in refs
    assert not any(reference.startswith(("health_check:", "dependency:")) for reference in refs)
    assert all({"hypothesis", "explanation"} <= set(item) for item in result["alternative_hypotheses"])
    assert refreshed["state"] == "ESCALATED" and refreshed["escalation_status"] == "created"
    assert refreshed["probable_root_cause"] == result["probable_root_cause"]
    assert refreshed["recovery_recommendation"] == "escalate_to_administrator"


@pytest.mark.asyncio
async def test_telemetry_without_an_indicator_is_still_investigated_without_threat_intelligence():
    async with new_client() as client:
        incidents = await run_scenario(client, "dependency_failure")
        incident = by_rule(incidents, "dependency_failure")
        body = (await client.post(f"/api/v1/incidents/{incident['id']}/investigations")).json()

    assert body["status"] == "completed"
    assert body["result"]["recommended_action"] == "restore_demo_dependency"
    assert not any(reference.startswith("threat_intel:") for reference in body["result"]["evidence_references"])


@pytest.mark.asyncio
async def test_incident_created_before_enrichment_is_enriched_at_investigation_time():
    async with new_client() as client:
        async with session_factory() as session:
            service = await session.scalar(select(Service).where(Service.name == "Checkout API"))
            legacy = Incident(
                service_id=service.id,
                incident_type="authentication_failure",
                severity="high",
                state="DETECTED",
                summary="Repeated authentication failure from an unusual source",
                diagnostic_evidence=json.dumps(
                    {"event_id": str(uuid4()), "metadata": {"source_ip": DEMO_BRUTE_FORCE_SOURCE}, "simulated": True}
                ),
                deduplication_key=f"legacy-{uuid4()}",
                detection_rule="repeated_failed_authentication",
                detection_timestamp=datetime.now(timezone.utc),
                is_demo=True,
            )
            session.add(legacy)
            await session.commit()
            legacy_id = legacy.id
        body = (await client.post(f"/api/v1/incidents/{legacy_id}/investigations")).json()

    assert body["status"] == "completed"
    assert f"threat_intel:{DEMO_BRUTE_FORCE_SOURCE}" in body["result"]["evidence_references"]


@pytest.mark.asyncio
async def test_health_check_incident_investigation_is_unchanged():
    async with new_client() as client:
        service = (
            await client.post(
                "/api/v1/services",
                json={"name": f"Enrichment {uuid4()}", "environment": "demo", "simulation_status": True},
            )
        ).json()
        await client.post(
            f"/api/v1/demo/services/{service['id']}/fault", headers=ADMIN, json={"scenario": "dependency_unavailable"}
        )
        incident = next(
            item for item in (await client.get("/api/v1/incidents")).json() if item["service_id"] == service["id"]
        )
        body = (await client.post(f"/api/v1/incidents/{incident['id']}/investigations")).json()

    assert body["status"] == "completed"
    assert body["result"]["recommended_action"] == "restore_demo_dependency"
    assert any(reference.startswith("health_check:") for reference in body["result"]["evidence_references"])
    assert not any(reference.startswith(("telemetry:", "threat_intel:")) for reference in body["result"]["evidence_references"])


# --- Local provider, in isolation ---------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provider_is_deterministic_and_threat_match_raises_confidence():
    provider = LocalDemoProvider()
    with_intel = await provider.investigate(telemetry_input(threat_intelligence=[SUSPICIOUS_INTEL]))
    again = await provider.investigate(telemetry_input(threat_intelligence=[SUSPICIOUS_INTEL]))
    without_intel = await provider.investigate(telemetry_input())

    assert with_intel == again
    assert with_intel.confidence_estimate == 0.9 and without_intel.confidence_estimate == 0.8
    assert "threat_intel:198.51.100.23" in with_intel.evidence_references
    assert "threat_intel:198.51.100.23" not in without_intel.evidence_references
    assert any("offline sample dataset" in risk for risk in with_intel.potential_risks)


@pytest.mark.asyncio
async def test_provider_reports_an_unmatched_indicator_without_claiming_malice():
    unknown = {"evidence_id": "threat_intel:192.0.2.55", "indicator": "192.0.2.55", "matched": False, "reputation": "unknown", "confidence": 0}
    result = await LocalDemoProvider().investigate(telemetry_input(threat_intelligence=[unknown]))

    assert "no entry in the offline threat-intelligence dataset" in result.root_cause_explanation
    assert result.confidence_estimate == 0.8


@pytest.mark.asyncio
async def test_provider_never_recommends_an_action_outside_the_allowlist_and_flags_unknown_rules():
    provider = LocalDemoProvider()
    configuration_drift = telemetry_input(available_recovery_actions=["restart_demo_application"])
    configuration_drift.telemetry_evidence[0].update(rule="configuration_change", resource_type="firewall")
    restricted = await provider.investigate(configuration_drift)
    unknown_rule = telemetry_input()
    unknown_rule.telemetry_evidence[0]["rule"] = "not_a_real_rule"
    unknown = await provider.investigate(unknown_rule)

    assert restricted.recommended_action == "none" and restricted.human_intervention_recommended is True
    assert unknown.recommended_action == "none"
    assert unknown.confidence_estimate < get_settings().ai_confidence_threshold
