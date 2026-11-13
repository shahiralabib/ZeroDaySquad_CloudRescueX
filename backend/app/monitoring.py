import asyncio
import json
import logging
import time
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.database import DemoFault, HealthCheck, Incident, IncidentEvent, Service
from app.domain import IncidentState, validate_transition

logger = logging.getLogger("cloudrescue.monitoring")

# Health monitoring only opens and resolves its own incidents. Telemetry detections (other rules) on
# the same service are independent and must neither suppress an outage incident nor be auto-resolved by one.
HEALTH_CHECK_RULE = "health_check_failure"


class HealthObservation:
    def __init__(self, status: str, response_time_ms: float, error: str | None, evidence: dict[str, object]):
        self.status = status
        self.response_time_ms = response_time_ms
        self.error = error
        self.evidence = evidence


class DemoHealthAdapter:
    async def check(self, session: AsyncSession, service: Service) -> HealthObservation:
        started = time.perf_counter()
        fault = await session.scalar(select(DemoFault).where(DemoFault.service_id == service.id))
        scenario = fault.scenario if fault else "healthy"
        await asyncio.sleep(0)
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        if scenario == "healthy":
            return HealthObservation("healthy", elapsed, None, {"scenario": scenario, "simulated": True})
        messages = {
            "service_unavailable": "Simulated service is unavailable",
            "configuration_failure": "Simulated configuration is invalid",
            "dependency_unavailable": "Simulated dependency is unavailable",
        }
        return HealthObservation("unhealthy", elapsed, messages[scenario], {"scenario": scenario, "simulated": True})


class MonitoringEngine:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession], enabled: bool = True):
        self.session_factory = session_factory
        self.enabled = enabled
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.adapter = DemoHealthAdapter()
        self._last_checked: dict[int, float] = {}

    async def start(self) -> None:
        if self.enabled and self._task is None:
            self._stop_event.clear()
            self._task = asyncio.create_task(self.run(), name="cloudrescue-monitoring")

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task:
            await self._task
            self._task = None

    async def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                await self.check_all()
            except Exception:
                logger.exception("Monitoring cycle failed")
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=1)
            except asyncio.TimeoutError:
                continue

    async def check_all(self) -> None:
        now = time.monotonic()
        async with self.session_factory() as session:
            services = list((await session.scalars(select(Service).where(Service.environment == "demo"))).all())
        for service in services:
            last_checked = self._last_checked.get(service.id, 0)
            if now - last_checked < service.monitoring_interval_seconds:
                continue
            try:
                await self.check_service(service.id)
                self._last_checked[service.id] = time.monotonic()
            except Exception:
                logger.exception("Service health check failed", extra={"service_id": service.id})

    async def check_service(self, service_id: int) -> HealthCheck:
        async with self.session_factory() as session:
            check = await self.check_service_in_session(session, service_id)
            await session.commit()
            await session.refresh(check)
            return check

    async def check_service_in_session(self, session: AsyncSession, service_id: int) -> HealthCheck:
        """Run a health check without opening or committing a nested session."""
        service = await session.get(Service, service_id)
        if service is None:
            raise ValueError(f"Service {service_id} was not found")
        try:
            observation = await asyncio.wait_for(
                self.adapter.check(session, service),
                timeout=service.health_check_timeout_seconds,
            )
        except asyncio.TimeoutError:
            observation = HealthObservation(
                "unhealthy",
                service.health_check_timeout_seconds * 1000,
                "Health check timed out",
                {"timeout_seconds": service.health_check_timeout_seconds, "simulated": service.simulation_status},
            )
        now = datetime.now(timezone.utc)
        check = HealthCheck(
            service_id=service.id,
            status=observation.status,
            response_time_ms=observation.response_time_ms,
            observed_at=now,
            error_message=observation.error,
            evidence=json.dumps(observation.evidence),
            simulated=service.simulation_status,
        )
        session.add(check)
        if observation.status == "healthy":
            recovered = service.status != "healthy" or service.consecutive_failure_count > 0
            service.status = "healthy"
            service.consecutive_failure_count = 0
            service.last_successful_check = now
            if recovered:
                await self._recover_open_incident(session, service, now)
        else:
            service.status = "unhealthy"
            service.consecutive_failure_count += 1
            service.last_failed_check = now
            if service.consecutive_failure_count >= service.failure_threshold:
                await self._open_incident_if_needed(session, service, observation, now)
        await session.flush()
        return check

    async def _open_incident_if_needed(
        self, session: AsyncSession, service: Service, observation: HealthObservation, now: datetime
    ) -> None:
        existing = await session.scalar(
            select(Incident)
            .where(Incident.service_id == service.id)
            .where(Incident.detection_rule == HEALTH_CHECK_RULE)
            .where(Incident.state.not_in([IncidentState.RESOLVED, IncidentState.ESCALATED]))
            .order_by(Incident.detection_timestamp.desc())
        )
        if existing:
            return
        incident_type = observation.evidence.get("scenario", "service_unavailable")
        incident = Incident(
            service_id=service.id,
            incident_type=str(incident_type),
            severity="high" if incident_type in {"service_unavailable", "dependency_unavailable"} else "medium",
            state=IncidentState.DETECTED,
            summary=observation.error or "Service health check failed",
            description=observation.error or "The service failed its health check.",
            diagnostic_evidence=json.dumps(observation.evidence),
            detection_timestamp=now,
            deduplication_key=f"service:{service.id}:outage",
            is_demo=service.simulation_status,
        )
        session.add(incident)
        await session.flush()
        session.add(
            IncidentEvent(
                incident_id=incident.id,
                event_type="DETECTION",
                description=incident.summary,
                metadata_json=json.dumps({"health_check_status": observation.status, "simulated": incident.is_demo}),
                created_at=now,
            )
        )

    async def _recover_open_incident(self, session: AsyncSession, service: Service, now: datetime) -> None:
        incident = await session.scalar(
            select(Incident)
            .where(Incident.service_id == service.id)
            .where(Incident.detection_rule == HEALTH_CHECK_RULE)
            .where(Incident.state.not_in([IncidentState.RESOLVED, IncidentState.ESCALATED]))
            .order_by(Incident.detection_timestamp.desc())
        )
        if incident is None:
            return
        if incident.state != IncidentState.VERIFYING:
            if incident.state in {IncidentState.DETECTED, IncidentState.INVESTIGATING, IncidentState.FAILED}:
                validate_transition(incident.state, IncidentState.VERIFYING)
                incident.state = IncidentState.VERIFYING
        validate_transition(incident.state, IncidentState.RESOLVED)
        incident.state = IncidentState.RESOLVED
        incident.resolution_timestamp = now
        incident.verification_outcome = "Service health recovered independently."
        session.add(
            IncidentEvent(
                incident_id=incident.id,
                event_type="SERVICE_RECOVERED",
                description="Health check succeeded after an outage.",
                metadata_json=json.dumps({"status": "healthy", "simulated": service.simulation_status}),
                created_at=now,
            )
        )
        session.add(
            IncidentEvent(
                incident_id=incident.id,
                event_type="RESOLUTION",
                description="Incident resolved after independent service recovery verification.",
                metadata_json=json.dumps({"verification": "health_check"}),
                created_at=now,
            )
        )
