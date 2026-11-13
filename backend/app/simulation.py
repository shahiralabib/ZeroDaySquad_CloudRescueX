from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import Incident, IncidentEvent, InfrastructureResource, Service, SimulationState, TelemetryEvent
from app.domain import IncidentState
from app.threat_intelligence import enrich_telemetry_metadata, threat_intelligence_factor

RESOURCE_DEFINITIONS = (
    ("sim-firewall-01", "Edge Firewall", "firewall", None),
    ("sim-vpn-01", "Remote Access VPN", "vpn_gateway", "sim-firewall-01"),
    ("sim-web-01", "Public Web Server", "web_server", "sim-firewall-01"),
    ("sim-auth-01", "Authentication Service", "authentication_service", "sim-web-01"),
    ("sim-db-01", "Customer Database", "database_server", "sim-web-01"),
)
SCENARIOS = {
    "baseline",
    "authentication_attack",
    "network_disruption",
    "resource_pressure",
    "configuration_drift",
    "dependency_failure",
    "unusual_traffic",
}


# Reserved documentation addresses that exist as sample indicators in the offline threat dataset.
DEMO_BRUTE_FORCE_SOURCE = "198.51.100.23"
DEMO_UNUSUAL_TRAFFIC_SOURCE = "203.0.113.44"

# Demo mapping from a simulated infrastructure asset to the demo service it supports. Telemetry
# incidents are raised against the mapped service. If a service is missing (custom databases),
# detection falls back to the first demo service.
RESOURCE_SERVICE_NAMES = {
    "sim-auth-01": "Checkout API",
    "sim-web-01": "Customer Portal",
    "sim-firewall-01": "Customer Portal",
    "sim-db-01": "Payments Worker",
    "sim-vpn-01": "Payments Worker",
}


def simulation_run_id(state: SimulationState | None) -> str:
    """Identify one simulation run. Start stamps `started_at` and Reset clears it, so each run has its own value."""
    started = state.started_at if state is not None else None
    if started is None:
        return "norun"
    if started.tzinfo is not None:
        started = started.astimezone(timezone.utc).replace(tzinfo=None)
    return started.strftime("%Y%m%dT%H%M%S%f")


@dataclass(frozen=True)
class GeneratedEvent:
    resource_key: str
    category: str
    event_type: str
    severity: str
    summary: str
    metadata: dict[str, object]


def _scenario_events(scenario: str, rng: random.Random, count: int) -> list[GeneratedEvent]:
    resources = [definition[0] for definition in RESOURCE_DEFINITIONS]
    events: list[GeneratedEvent] = []
    for index in range(count):
        resource_key = resources[index % len(resources)]
        if scenario == "authentication_attack":
            failed = index % 3 != 2
            events.append(
                GeneratedEvent(
                    "sim-auth-01",
                    "authentication",
                    "authentication_failure" if failed else "suspicious_login",
                    "high" if failed else "critical",
                    "Repeated authentication failure from an unusual source"
                    if failed
                    else "Suspicious login pattern detected",
                    {
                        # Failed logins come from the sample indicator the offline dataset describes as modelling
                        # repeated authentication failures; suspicious logins keep varied documentation-range IPs.
                        "source_ip": DEMO_BRUTE_FORCE_SOURCE if failed else f"198.51.100.{10 + index % 20}",
                        "username": f"synthetic-user-{index % 4}",
                        "attempt": index + 1,
                    },
                )
            )
        elif scenario == "network_disruption":
            events.append(
                GeneratedEvent(
                    "sim-firewall-01" if index % 2 == 0 else "sim-vpn-01",
                    "network",
                    "network_connection",
                    "medium" if index % 2 == 0 else "high",
                    "Synthetic network connection state changed",
                    {"protocol": "tcp", "port": 443, "action": "blocked" if index % 2 == 0 else "timeout"},
                )
            )
        elif scenario == "resource_pressure":
            cpu = round(82 + rng.random() * 17, 2)
            memory = round(78 + rng.random() * 20, 2)
            events.append(
                GeneratedEvent(
                    "sim-web-01" if index % 2 == 0 else "sim-db-01",
                    "metric",
                    "cpu_memory_metric",
                    "high" if cpu >= 90 or memory >= 90 else "medium",
                    "Synthetic resource utilization exceeded the normal operating range",
                    {"cpu_percent": cpu, "memory_percent": memory, "unit": "percent"},
                )
            )
        elif scenario == "configuration_drift":
            events.append(
                GeneratedEvent(
                    resource_key,
                    "configuration",
                    "configuration_change",
                    "medium",
                    "Synthetic configuration changed from the known-good baseline",
                    {"setting": "access_policy" if index % 2 == 0 else "max_connections", "actor": "simulation"},
                )
            )
        elif scenario == "dependency_failure":
            events.append(
                GeneratedEvent(
                    "sim-db-01",
                    "dependency",
                    "dependency_failure",
                    "high",
                    "Synthetic upstream dependency failed health checks",
                    {"dependency": "customer-database", "availability": "unavailable"},
                )
            )
        elif scenario == "unusual_traffic":
            events.append(
                GeneratedEvent(
                    "sim-firewall-01",
                    "network",
                    "unusual_traffic",
                    "high",
                    "Synthetic traffic exceeded the expected baseline",
                    {
                        "connections_per_minute": 1200 + index * 25,
                        "baseline": 240,
                        "direction": "inbound",
                        "source_ip": DEMO_UNUSUAL_TRAFFIC_SOURCE,
                    },
                )
            )
        else:
            if index % 2 == 0:
                events.append(
                    GeneratedEvent(
                        resource_key,
                        "availability",
                        "service_availability",
                        "info",
                        "Synthetic service availability heartbeat",
                        {"availability": "available", "latency_ms": round(18 + rng.random() * 24, 2)},
                    )
                )
            else:
                events.append(
                    GeneratedEvent(
                        "sim-auth-01",
                        "authentication",
                        "authentication_success",
                        "info",
                        "Synthetic authentication succeeded",
                        {"source_ip": "192.0.2.10", "username": "synthetic-operator"},
                    )
                )
    return events


async def ensure_simulation_data(session: AsyncSession) -> SimulationState:
    resources = list((await session.scalars(select(InfrastructureResource))).all())
    by_key = {resource.resource_key: resource for resource in resources}
    for key, name, resource_type, parent_key in RESOURCE_DEFINITIONS:
        if key not in by_key:
            resource = InfrastructureResource(
                resource_key=key,
                name=name,
                resource_type=resource_type,
                configuration_json=json.dumps({"managed_by": "local_simulation"}),
                metadata_json=json.dumps({"source": "local_simulation", "synthetic": True}),
            )
            if parent_key and parent_key in by_key:
                resource.parent = by_key[parent_key]
            session.add(resource)
            by_key[key] = resource
    state = await session.get(SimulationState, 1)
    if state is None:
        state = SimulationState(id=1, scenario="baseline", status="stopped", seed=1)
        session.add(state)
    await session.flush()
    return state


async def generate_events(
    session: AsyncSession,
    state: SimulationState,
    event_count: int,
    seed: int | None = None,
) -> list[TelemetryEvent]:
    if state.status != "running":
        raise ValueError("Simulation must be running before events can be generated.")
    if seed is not None:
        state.seed = seed
    rng = random.Random(state.seed + state.tick_count)
    resources = {
        resource.resource_key: resource
        for resource in (await session.scalars(select(InfrastructureResource))).all()
    }
    generated = _scenario_events(state.scenario, rng, event_count)
    now = datetime.now(timezone.utc)
    records: list[TelemetryEvent] = []
    for index, item in enumerate(generated):
        resource = resources[item.resource_key]
        resource.status = "healthy" if item.severity == "info" else "degraded"
        record = TelemetryEvent(
            event_id=str(uuid5(NAMESPACE_URL, f"{state.scenario}:{state.seed}:{state.tick_count}:{index}")),
            resource_id=resource.id,
            category=item.category,
            event_type=item.event_type,
            severity=item.severity,
            summary=item.summary,
            observed_at=now - timedelta(seconds=event_count - index),
            source="local_simulation",
            metadata_json=json.dumps(item.metadata),
            correlation_id=str(uuid5(NAMESPACE_URL, f"{state.scenario}:{state.seed}:{state.tick_count}:correlation")),
            simulated=True,
        )
        session.add(record)
        records.append(record)
    state.tick_count += 1
    await session.flush()
    return records


async def detect_telemetry(
    session: AsyncSession,
    records: list[TelemetryEvent],
) -> list[Incident]:
    if not records:
        return []
    services = list(
        (
            await session.scalars(
                select(Service)
                .where(Service.environment == "demo", Service.simulation_status.is_(True))
                .order_by(Service.id)
            )
        ).all()
    )
    if not services:
        return []
    services_by_name = {service.name: service for service in services}
    resources_by_id = {
        resource.id: resource
        for resource in (
            await session.scalars(
                select(InfrastructureResource).where(
                    InfrastructureResource.id.in_({event.resource_id for event in records})
                )
            )
        ).all()
    }
    run_id = simulation_run_id(await session.get(SimulationState, 1))
    incidents: list[Incident] = []
    rules = {
        "authentication_failure": "repeated_failed_authentication",
        "suspicious_login": "suspicious_login_pattern",
        "network_connection": "unusual_network_connection",
        "unusual_traffic": "unusual_network_traffic",
        "cpu_memory_metric": "resource_exhaustion",
        "configuration_change": "configuration_change",
        "dependency_failure": "dependency_failure",
        "service_availability": "service_availability",
    }
    severity_weights = {"info": 10, "medium": 45, "high": 70, "critical": 90}
    for event in records:
        metadata = json.loads(event.metadata_json or "{}")
        rule = rules.get(event.event_type)
        if rule is None or event.severity == "info":
            continue
        # The run id keeps repeated runs (same scenario and seed after a Reset) from colliding with the
        # incidents of earlier runs, while events of one run still collapse into a single incident.
        deduplication_key = f"telemetry:{run_id}:{rule}:{event.resource_id}:{event.correlation_id}"
        duplicate = await session.scalar(
            select(Incident).where(Incident.deduplication_key == deduplication_key)
        )
        if duplicate:
            continue
        factors = {
            "asset_criticality": 80 if event.category in {"authentication", "dependency"} else 60,
            "detection_confidence": 90 if event.severity in {"high", "critical"} else 70,
            "severity": severity_weights.get(event.severity, 50),
            "exploitability": 85 if event.category == "authentication" else 60,
            "business_impact": 80 if event.category in {"availability", "dependency"} else 55,
            "blast_radius": 75 if event.category in {"network", "dependency"} else 45,
        }
        # Offline threat-intelligence enrichment of the event's source indicator (events without one are unaffected).
        finding = enrich_telemetry_metadata(metadata)
        if finding is not None:
            factors["threat_intelligence"] = threat_intelligence_factor(finding)
        # The score is the mean of the factors, so every contribution is visible in priority_factors.
        score = round(sum(factors.values()) / len(factors), 2)
        resource = resources_by_id.get(event.resource_id)
        resource_key = resource.resource_key if resource is not None else None
        service = services_by_name.get(RESOURCE_SERVICE_NAMES.get(resource_key or "", "")) or services[0]
        evidence_references = [f"telemetry:{event.event_id}"]
        if resource_key:
            evidence_references.append(f"resource:{resource_key}")
        if finding is not None and finding.get("matched"):
            evidence_references.append(f"threat_intel:{finding['indicator']}")
        diagnostic_evidence: dict[str, object] = {
            "event_id": event.event_id,
            "resource_key": resource_key,
            "metadata": metadata,
            "simulated": True,
        }
        if finding is not None:
            diagnostic_evidence["threat_intelligence"] = finding
        incident = Incident(
            service_id=service.id,
            incident_type=event.event_type,
            severity=event.severity,
            state=IncidentState.DETECTED,
            summary=event.summary,
            description=f"Local detection rule '{rule}' matched persisted synthetic telemetry.",
            diagnostic_evidence=json.dumps(diagnostic_evidence),
            detection_timestamp=event.observed_at,
            deduplication_key=deduplication_key,
            detection_rule=rule,
            evidence_references_json=json.dumps(evidence_references),
            priority_score=score,
            priority_factors_json=json.dumps(factors),
            is_demo=True,
        )
        session.add(incident)
        await session.flush()
        session.add(
            IncidentEvent(
                incident_id=incident.id,
                event_type="DETECTION",
                description=incident.summary,
                metadata_json=json.dumps(
                    {
                        "rule": rule,
                        "telemetry_event_id": event.event_id,
                        "resource_key": resource_key,
                        "simulated": True,
                    }
                ),
                created_at=event.observed_at,
            )
        )
        incidents.append(incident)
    return incidents


async def reset_simulation(session: AsyncSession) -> SimulationState:
    state = await ensure_simulation_data(session)
    await session.execute(delete(TelemetryEvent))
    for resource in (await session.scalars(select(InfrastructureResource))).all():
        resource.status = "healthy"
    state.scenario = "baseline"
    state.status = "stopped"
    state.seed = 1
    state.tick_count = 0
    state.started_at = None
    state.stopped_at = datetime.now(timezone.utc)
    await session.flush()
    return state


def telemetry_investigation_evidence(incident: Incident) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Telemetry and threat-intelligence evidence recorded on a telemetry-detected incident.

    Returns (telemetry_evidence, threat_intelligence) for the AI investigation. Incidents that were not
    created from telemetry (for example health-check outages) return two empty lists. Findings stored at
    detection time are reused; incidents created before enrichment existed are looked up from their metadata.
    """
    try:
        stored = json.loads(incident.diagnostic_evidence or "{}")
    except json.JSONDecodeError:
        return [], []
    if not isinstance(stored, dict) or not stored.get("event_id"):
        return [], []
    metadata = stored.get("metadata") if isinstance(stored.get("metadata"), dict) else {}
    telemetry = [
        {
            "evidence_id": f"telemetry:{stored['event_id']}",
            "resource_key": stored.get("resource_key"),
            "rule": incident.detection_rule,
            "event_type": incident.incident_type,
            "severity": incident.severity,
            "summary": incident.summary,
            "metadata": metadata,
        }
    ]
    finding = stored.get("threat_intelligence")
    if not isinstance(finding, dict):
        finding = enrich_telemetry_metadata(metadata)
    intelligence: list[dict[str, object]] = []
    if isinstance(finding, dict):
        intelligence.append({"evidence_id": f"threat_intel:{finding.get('indicator', 'unknown')}", **finding})
    return telemetry, intelligence
