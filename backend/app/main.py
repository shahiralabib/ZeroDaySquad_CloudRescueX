import json
import logging
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.ai import (
    AIProviderError,
    InvestigationInput,
    InvestigationResult,
    InvalidAIResponseError,
    LowConfidenceInvestigationError,
    get_provider,
)
from app.database import (
    DemoFault,
    HealthCheck,
    Incident,
    IncidentEvent,
    Investigation,
    RecoveryExecution,
    VerificationAttempt,
    Escalation,
    Notification,
    AuditEvent,
    RecoveryApproval,
    Service,
    engine,
    get_session,
    seed_demo_data,
    session_factory,
    InfrastructureResource,
    SimulationState,
    TelemetryEvent,
)
from app.domain import DEMO_SCENARIOS, IncidentState, TIMELINE_EVENT_TYPES, validate_transition
from app.logging import configure_logging
from app.monitoring import MonitoringEngine
from app.cloud_adapters import integration_statuses
from app.recovery import ACTION_CATALOG, PolicyRejected, affected_resource, execute_recovery, create_escalation, get_action, parameters_hash, validate_policy
from app.escalations import (
    STATUS_ACKNOWLEDGED,
    STATUS_REJECTED,
    EscalationConflict,
    EscalationNotFound,
    escalation_status,
    process_escalation,
    rejection_of,
)
from app.remediation import ESCALATE_TO_ADMINISTRATOR
from app.simulation import (
    SCENARIOS,
    detect_telemetry,
    ensure_simulation_data,
    generate_events,
    reset_simulation,
    telemetry_investigation_evidence,
)
from app.threat_intelligence import lookup_indicator
from app.schemas import (
    DashboardStatsResponse,
    DemoFaultRequest,
    ErrorResponse,
    HealthCheckResponse,
    HealthResponse,
    IncidentEventResponse,
    IncidentResponse,
    IncidentStateUpdate,
    OverviewResponse,
    ProviderStatusResponse,
    InvestigationResponse,
    RecoveryRequest,
    RecoveryActionResponse,
    RecoveryExecutionResponse,
    VerificationResponse,
    EscalationResponse,
    NotificationResponse,
    IntegrationStatusResponse,
    OperatingModeResponse,
    ServiceCreate,
    ServiceResponse,
    ServiceUpdate,
    InfrastructureResourceResponse,
    SimulationStartRequest,
    SimulationStateResponse,
    TelemetryEventResponse,
)

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger("cloudrescue.api")
monitoring = MonitoringEngine(session_factory, enabled=settings.monitoring_enabled)
_request_windows: dict[str, list[float]] = {}


def json_dict(value: str | None) -> dict[str, object]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {"raw": value}
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def service_response(service: Service) -> ServiceResponse:
    payload = {**service.__dict__, "health_check_config": json_dict(service.health_check_config)}
    return ServiceResponse.model_validate(payload)


def incident_response(incident: Incident, service_name: str) -> IncidentResponse:
    payload = {
        **incident.__dict__,
        "service_name": service_name,
        "diagnostic_evidence": json_dict(incident.diagnostic_evidence),
        "evidence_references": json.loads(incident.evidence_references_json or "[]"),
        "priority_factors": json_dict(incident.priority_factors_json),
    }
    return IncidentResponse.model_validate(payload)


def check_response(check: HealthCheck) -> HealthCheckResponse:
    return HealthCheckResponse.model_validate({**check.__dict__, "evidence": json_dict(check.evidence)})


def recovery_execution_response(record: RecoveryExecution) -> RecoveryExecutionResponse:
    return RecoveryExecutionResponse(
        id=record.id, incident_id=record.incident_id, service_id=record.service_id,
        action_id=record.action_id, parameters=json_dict(record.parameters_json),
        status=record.status, result=json_dict(record.result_json),
        error_message=record.error_message, started_at=record.started_at, completed_at=record.completed_at,
    )


def verification_response(record: VerificationAttempt) -> VerificationResponse:
    return VerificationResponse(
        id=record.id, incident_id=record.incident_id, execution_id=record.execution_id,
        outcome=record.outcome, successful_checks=record.successful_checks,
        required_checks=record.required_checks, evidence=json_dict(record.evidence_json),
        created_at=record.created_at,
    )


def escalation_response(record: Escalation) -> EscalationResponse:
    def json_value(value: str, fallback: object) -> object:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return fallback
    return EscalationResponse(
        id=record.id, incident_id=record.incident_id, reason=record.reason, severity=record.severity,
        evidence=json_value(record.evidence_json, {}), ai_findings=json_value(record.ai_findings_json, {}),
        attempted_actions=json_value(record.attempted_actions_json, []),
        policy_decisions=json_value(record.policy_decisions_json, []),
        recommended_next_steps=record.recommended_next_steps, acknowledged=record.acknowledged,
        assigned_administrator=record.assigned_administrator, escalated_at=record.escalated_at,
        acknowledged_at=record.acknowledged_at,
        status=escalation_status(record),
        rejection_reason=(rejection_of(record) or {}).get("reason"),
    )


def simulation_state_response(state: SimulationState) -> SimulationStateResponse:
    return SimulationStateResponse(
        scenario=state.scenario,
        status=state.status,
        seed=state.seed,
        tick_count=state.tick_count,
        started_at=state.started_at,
        stopped_at=state.stopped_at,
    )


def resource_response(resource: InfrastructureResource) -> InfrastructureResourceResponse:
    return InfrastructureResourceResponse(
        id=resource.id,
        resource_key=resource.resource_key,
        name=resource.name,
        resource_type=resource.resource_type,
        status=resource.status,
        environment=resource.environment,
        configuration=json_dict(resource.configuration_json),
        metadata=json_dict(resource.metadata_json),
        parent_resource_id=resource.parent_resource_id,
        simulated=resource.simulated,
        created_at=resource.created_at,
        updated_at=resource.updated_at,
    )


def telemetry_response(event: TelemetryEvent, resource_key: str) -> TelemetryEventResponse:
    return TelemetryEventResponse(
        event_id=event.event_id,
        resource_id=event.resource_id,
        resource_key=resource_key,
        category=event.category,
        event_type=event.event_type,
        severity=event.severity,
        summary=event.summary,
        observed_at=event.observed_at,
        source=event.source,
        metadata=json_dict(event.metadata_json),
        correlation_id=event.correlation_id,
        simulated=event.simulated,
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("Database in use: %s", settings.database_description)
    database_file = settings.database_file
    if database_file is not None and not database_file.exists():
        logger.warning(
            "Database file %s does not exist. Run 'alembic upgrade head' with the same DATABASE_URL before starting the API.",
            database_file,
        )
    await seed_demo_data()
    async with session_factory() as session:
        await ensure_simulation_data(session)
        await session.commit()
    await monitoring.start()
    try:
        yield
    finally:
        await monitoring.stop()
        await engine.dispose()


app = FastAPI(
    title=settings.app_name,
    version="0.2.0",
    lifespan=lifespan,
    responses={500: {"model": ErrorResponse}},
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def correlation_middleware(request: Request, call_next):
    correlation_id = request.headers.get("X-Correlation-ID", str(uuid4()))
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.request_max_body_bytes:
        return JSONResponse(status_code=413, content={"error": {"code": "REQUEST_TOO_LARGE", "message": "Request body exceeds the configured limit.", "correlation_id": correlation_id, "details": {}}})
    client_key = request.client.host if request.client else "unknown"
    now = time.monotonic()
    recent = [item for item in _request_windows.get(client_key, []) if now - item < 60]
    if len(recent) >= settings.rate_limit_per_minute:
        return JSONResponse(status_code=429, content={"error": {"code": "RATE_LIMITED", "message": "Too many requests.", "correlation_id": correlation_id, "details": {}}})
    recent.append(now)
    _request_windows[client_key] = recent
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled request error", extra={"correlation_id": correlation_id})
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "INTERNAL_ERROR", "message": "An unexpected error occurred", "correlation_id": correlation_id, "details": {}}},
        )
    response.headers["X-Correlation-ID"] = correlation_id
    return response


@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=settings.app_name,
        environment=settings.environment,
        mode=settings.operating_mode.upper(),
        simulated=settings.demo_mode,
        data_source=settings.data_source,
        database=settings.database_label,
    )


@app.get("/ready", response_model=HealthResponse, tags=["system"])
async def readiness(session: AsyncSession = Depends(get_session)) -> HealthResponse:
    await session.execute(text("SELECT 1"))
    return HealthResponse(
        status="ready",
        service=settings.app_name,
        environment=settings.environment,
        mode=settings.operating_mode.upper(),
        simulated=settings.demo_mode,
        data_source=settings.data_source,
        database=settings.database_label,
    )


api = APIRouter()


@api.get("/mode", response_model=OperatingModeResponse, tags=["system"])
async def operating_mode() -> OperatingModeResponse:
    return OperatingModeResponse(
        mode=settings.operating_mode.upper(),
        simulated=settings.demo_mode,
        data_source=settings.data_source,
        external_integrations_available=not settings.demo_mode,
    )


@api.get("/threat-intelligence/lookup", tags=["threat intelligence"])
async def threat_intelligence_lookup(indicator: str = Query(min_length=1, max_length=255)) -> dict[str, object]:
    return lookup_indicator(indicator)


@api.get("/simulation/status", response_model=SimulationStateResponse, tags=["simulation"])
async def simulation_status(session: AsyncSession = Depends(get_session)) -> SimulationStateResponse:
    state = await ensure_simulation_data(session)
    await session.commit()
    return simulation_state_response(state)


@api.get("/simulation/resources", response_model=list[InfrastructureResourceResponse], tags=["simulation"])
async def simulation_resources(session: AsyncSession = Depends(get_session)) -> list[InfrastructureResourceResponse]:
    await ensure_simulation_data(session)
    resources = list((await session.scalars(select(InfrastructureResource).order_by(InfrastructureResource.id))).all())
    await session.commit()
    return [resource_response(resource) for resource in resources]


@api.get("/simulation/resources/{resource_id}", response_model=InfrastructureResourceResponse, tags=["simulation"])
async def simulation_resource(resource_id: int, session: AsyncSession = Depends(get_session)) -> InfrastructureResourceResponse:
    await ensure_simulation_data(session)
    resource = await session.get(InfrastructureResource, resource_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="Simulation resource not found")
    await session.commit()
    return resource_response(resource)


@api.get("/simulation/events", response_model=list[TelemetryEventResponse], tags=["simulation"])
async def simulation_events(
    resource_id: int | None = Query(default=None, ge=1),
    category: str | None = Query(default=None, min_length=1, max_length=32),
    severity: str | None = Query(default=None, min_length=1, max_length=16),
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
) -> list[TelemetryEventResponse]:
    if start_time and end_time and start_time > end_time:
        raise HTTPException(status_code=422, detail="start_time must be before end_time")
    query = select(TelemetryEvent, InfrastructureResource.resource_key).join(
        InfrastructureResource, TelemetryEvent.resource_id == InfrastructureResource.id
    )
    if resource_id is not None:
        query = query.where(TelemetryEvent.resource_id == resource_id)
    if category is not None:
        query = query.where(TelemetryEvent.category == category)
    if severity is not None:
        query = query.where(TelemetryEvent.severity == severity)
    if start_time is not None:
        query = query.where(TelemetryEvent.observed_at >= start_time)
    if end_time is not None:
        query = query.where(TelemetryEvent.observed_at <= end_time)
    rows = (await session.execute(
        query.order_by(TelemetryEvent.observed_at.desc()).offset(offset).limit(limit)
    )).all()
    return [telemetry_response(event, resource_key) for event, resource_key in rows]


@api.post("/simulation/start", response_model=SimulationStateResponse, tags=["simulation"])
async def start_simulation(
    payload: SimulationStartRequest,
    x_demo_admin_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> SimulationStateResponse:
    require_demo_admin(x_demo_admin_token)
    if payload.scenario not in SCENARIOS:
        raise HTTPException(status_code=422, detail={"code": "UNKNOWN_SCENARIO", "scenarios": sorted(SCENARIOS)})
    state = await ensure_simulation_data(session)
    state.scenario = payload.scenario
    state.status = "running"
    state.seed = payload.seed
    state.started_at = datetime.now(timezone.utc)
    state.stopped_at = None
    records = await generate_events(session, state, payload.event_count, payload.seed)
    await detect_telemetry(session, records)
    await session.commit()
    return simulation_state_response(state)


@api.post("/simulation/tick", response_model=SimulationStateResponse, tags=["simulation"])
async def simulation_tick(
    x_demo_admin_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> SimulationStateResponse:
    require_demo_admin(x_demo_admin_token)
    state = await ensure_simulation_data(session)
    if state.status != "running":
        raise HTTPException(status_code=409, detail="Simulation must be running before a tick.")
    records = await generate_events(session, state, 10)
    await detect_telemetry(session, records)
    await session.commit()
    return simulation_state_response(state)


@api.post("/simulation/stop", response_model=SimulationStateResponse, tags=["simulation"])
async def stop_simulation(
    x_demo_admin_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> SimulationStateResponse:
    require_demo_admin(x_demo_admin_token)
    state = await ensure_simulation_data(session)
    state.status = "stopped"
    state.stopped_at = datetime.now(timezone.utc)
    await session.commit()
    return simulation_state_response(state)


@api.post("/simulation/reset", response_model=SimulationStateResponse, tags=["simulation"])
async def reset_local_simulation(
    x_demo_admin_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> SimulationStateResponse:
    require_demo_admin(x_demo_admin_token)
    state = await reset_simulation(session)
    await session.commit()
    return simulation_state_response(state)


@api.get("/overview", response_model=OverviewResponse, tags=["dashboard"])
async def overview(session: AsyncSession = Depends(get_session)) -> OverviewResponse:
    services = list((await session.scalars(select(Service).order_by(Service.name))).all())
    rows = (await session.execute(select(Incident, Service.name).join(Service).order_by(Incident.detection_timestamp.desc()).limit(10))).all()
    active = await session.scalar(select(func.count(Incident.id)).where(Incident.state.not_in([IncidentState.RESOLVED, IncidentState.ESCALATED])))
    healthy = await session.scalar(select(func.count(Service.id)).where(Service.status == "healthy"))
    return OverviewResponse(
        services=[service_response(service) for service in services],
        incidents=[incident_response(incident, name) for incident, name in rows],
        metrics={"active_incidents": active or 0, "healthy_services": healthy or 0, "total_services": len(services)},
        seeded_demo_data=settings.seed_demo_data,
    )


@api.get("/dashboard/stats", response_model=DashboardStatsResponse, tags=["dashboard"])
async def dashboard_stats(session: AsyncSession = Depends(get_session)) -> DashboardStatsResponse:
    hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    total = await session.scalar(select(func.count(Service.id)))
    healthy = await session.scalar(select(func.count(Service.id)).where(Service.status == "healthy"))
    active = await session.scalar(select(func.count(Incident.id)).where(Incident.state.not_in([IncidentState.RESOLVED, IncidentState.ESCALATED])))
    resolved = await session.scalar(select(func.count(Incident.id)).where(Incident.state == IncidentState.RESOLVED))
    failures = await session.scalar(select(func.count(HealthCheck.id)).where(HealthCheck.status == "unhealthy", HealthCheck.observed_at >= hour_ago))
    unhealthy = await session.scalar(select(func.count(Service.id)).where(Service.status != "healthy"))
    escalated = await session.scalar(select(func.count(Incident.id)).where(Incident.state == IncidentState.ESCALATED))
    incidents = list((await session.scalars(select(Incident))).all())
    severity_distribution: dict[str, int] = {}
    detection_counts: dict[str, int] = {}
    for incident in incidents:
        severity_distribution[incident.severity] = severity_distribution.get(incident.severity, 0) + 1
        detection_counts[incident.incident_type] = detection_counts.get(incident.incident_type, 0) + 1
    recovery_rows = list((await session.scalars(select(RecoveryExecution))).all())
    recovery_activity: dict[str, int] = {}
    for execution in recovery_rows:
        day = (execution.started_at or datetime.now(timezone.utc)).date().isoformat()
        recovery_activity[day] = recovery_activity.get(day, 0) + 1
    verified_durations = [
        (incident.resolution_timestamp - incident.detection_timestamp).total_seconds()
        for incident in incidents
        if incident.resolution_timestamp and incident.detection_timestamp
    ]
    detected_durations = [
        max(0, (incident.detection_timestamp - incident.created_at).total_seconds())
        for incident in incidents
        if incident.created_at and incident.detection_timestamp
    ]
    completed_recoveries = [item for item in recovery_rows if item.status == "completed"]
    return DashboardStatsResponse(
        total_services=total or 0,
        healthy_services=healthy or 0,
        active_incidents=active or 0,
        resolved_incidents=resolved or 0,
        failed_checks_last_hour=failures or 0,
        unhealthy_services=unhealthy or 0,
        escalated_incidents=escalated or 0,
        average_verified_recovery_seconds=(
            sum(verified_durations) / len(verified_durations) if verified_durations else None
        ),
        severity_distribution=severity_distribution,
        recovery_activity=[{"date": date, "count": count} for date, count in sorted(recovery_activity.items())],
        detection_counts=detection_counts,
        mean_time_to_detect_seconds=(
            sum(detected_durations) / len(detected_durations) if detected_durations else None
        ),
        recovery_success_rate=(
            len(completed_recoveries) / len(recovery_rows) if recovery_rows else None
        ),
    )


@api.get("/services", response_model=list[ServiceResponse], tags=["services"])
async def list_services(session: AsyncSession = Depends(get_session)) -> list[ServiceResponse]:
    records = list((await session.scalars(select(Service).order_by(Service.name))).all())
    return [service_response(record) for record in records]


@api.get("/services/{service_id}", response_model=ServiceResponse, tags=["services"])
async def get_service(service_id: int, session: AsyncSession = Depends(get_session)) -> ServiceResponse:
    service = await session.get(Service, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    return service_response(service)


@api.post("/services", response_model=ServiceResponse, status_code=201, tags=["services"])
async def create_service(payload: ServiceCreate, session: AsyncSession = Depends(get_session)) -> ServiceResponse:
    service = Service(
        name=payload.name,
        description=payload.description,
        environment=payload.environment,
        health_check_config=json.dumps(payload.health_check_config),
        health_check_timeout_seconds=payload.health_check_timeout_seconds,
        failure_threshold=payload.failure_threshold,
        monitoring_interval_seconds=payload.monitoring_interval_seconds,
        simulation_status=payload.simulation_status,
    )
    session.add(service)
    await session.flush()
    session.add(DemoFault(service_id=service.id, scenario="healthy"))
    await session.commit()
    await session.refresh(service)
    return service_response(service)


@api.patch("/services/{service_id}", response_model=ServiceResponse, tags=["services"])
async def update_service(service_id: int, payload: ServiceUpdate, session: AsyncSession = Depends(get_session)) -> ServiceResponse:
    service = await session.get(Service, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    updates = payload.model_dump(exclude_unset=True)
    if "health_check_config" in updates:
        updates["health_check_config"] = json.dumps(updates["health_check_config"])
    for key, value in updates.items():
        if key == "enabled":
            continue
        setattr(service, key, value)
    await session.commit()
    await session.refresh(service)
    return service_response(service)


@api.get("/services/{service_id}/health", response_model=list[HealthCheckResponse], tags=["health checks"])
async def service_health(service_id: int, session: AsyncSession = Depends(get_session)) -> list[HealthCheckResponse]:
    if await session.get(Service, service_id) is None:
        raise HTTPException(status_code=404, detail="Service not found")
    checks = list((await session.scalars(select(HealthCheck).where(HealthCheck.service_id == service_id).order_by(HealthCheck.observed_at.desc()).limit(50))).all())
    return [check_response(check) for check in checks]


@api.post("/services/{service_id}/health", response_model=HealthCheckResponse, tags=["health checks"])
async def run_health_check(service_id: int) -> HealthCheckResponse:
    try:
        return check_response(await monitoring.check_service(service_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@api.get("/incidents", response_model=list[IncidentResponse], tags=["incidents"])
async def list_incidents(session: AsyncSession = Depends(get_session)) -> list[IncidentResponse]:
    rows = (await session.execute(select(Incident, Service.name).join(Service).order_by(Incident.detection_timestamp.desc()))).all()
    return [incident_response(incident, name) for incident, name in rows]


@api.get("/incidents/{incident_id}", response_model=IncidentResponse, tags=["incidents"])
async def get_incident(incident_id: int, session: AsyncSession = Depends(get_session)) -> IncidentResponse:
    row = (await session.execute(select(Incident, Service.name).join(Service).where(Incident.id == incident_id))).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident_response(row[0], row[1])


@api.patch("/incidents/{incident_id}/state", response_model=IncidentResponse, tags=["incidents"])
async def transition_incident(incident_id: int, payload: IncidentStateUpdate, session: AsyncSession = Depends(get_session)) -> IncidentResponse:
    row = (await session.execute(select(Incident, Service.name).join(Service).where(Incident.id == incident_id))).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident, service_name = row
    try:
        validate_transition(incident.state, payload.target_state)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    incident.state = payload.target_state
    if payload.target_state == IncidentState.RESOLVED:
        incident.resolution_timestamp = datetime.now(timezone.utc)
    event_type = "RESOLUTION" if payload.target_state == IncidentState.RESOLVED else "POLICY_DECISION"
    if event_type not in TIMELINE_EVENT_TYPES:
        event_type = "POLICY_DECISION"
    session.add(IncidentEvent(incident_id=incident.id, event_type=event_type, description=payload.description or f"Incident moved to {payload.target_state}.", metadata_json=json.dumps({"target_state": payload.target_state})))
    await session.commit()
    return incident_response(incident, service_name)


@api.get("/incidents/{incident_id}/timeline", response_model=list[IncidentEventResponse], tags=["incident timeline"])
async def incident_timeline(incident_id: int, session: AsyncSession = Depends(get_session)) -> list[IncidentEventResponse]:
    if await session.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    events = list((await session.scalars(select(IncidentEvent).where(IncidentEvent.incident_id == incident_id).order_by(IncidentEvent.created_at))).all())
    return [IncidentEventResponse.model_validate({**event.__dict__, "metadata": json_dict(event.metadata_json)}) for event in events]


async def build_investigation_input(session: AsyncSession, incident: Incident, service: Service) -> InvestigationInput:
    checks = list(
        (
            await session.scalars(
                select(HealthCheck)
                .where(HealthCheck.service_id == service.id)
                .order_by(HealthCheck.observed_at.desc())
                .limit(20)
            )
        ).all()
    )
    incidents = list(
        (
            await session.scalars(
                select(Incident)
                .where(Incident.service_id == service.id)
                .order_by(Incident.detection_timestamp.desc())
                .limit(10)
            )
        ).all()
    )
    fault = await session.scalar(select(DemoFault).where(DemoFault.service_id == service.id))
    telemetry_evidence, threat_intelligence = telemetry_investigation_evidence(incident)
    if telemetry_evidence:
        # The affected asset's type decides which recovery actions can apply, so the investigation needs it.
        asset = await affected_resource(session, incident)
        if asset is not None:
            telemetry_evidence[0]["resource_key"] = telemetry_evidence[0].get("resource_key") or asset.resource_key
            telemetry_evidence[0]["resource_type"] = asset.resource_type
    return InvestigationInput(
        service_metadata={
            "id": service.id,
            "name": service.name,
            "description": service.description,
            "environment": service.environment,
            "status": service.status,
            "simulation_status": service.simulation_status,
            "consecutive_failure_count": service.consecutive_failure_count,
        },
        health_checks=[
            {
                "evidence_id": f"health_check:{check.id}",
                "status": check.status,
                "response_time_ms": check.response_time_ms,
                "observed_at": check.observed_at,
                "error_message": check.error_message,
                "evidence": json_dict(check.evidence),
            }
            for check in checks
        ],
        application_logs=[],
        metrics={},
        dependency_health={"demo_fault": fault.scenario if fault else "unknown"},
        recent_incidents=[
            {"incident_id": item.id, "state": item.state, "summary": item.summary}
            for item in incidents
            if item.id != incident.id
        ],
        available_recovery_actions=list(ACTION_CATALOG) if service.simulation_status else [],
        telemetry_evidence=telemetry_evidence,
        threat_intelligence=threat_intelligence,
    )


def investigation_response(record: Investigation) -> InvestigationResponse:
    result = None
    if record.result_json and record.status in {"completed", "low_confidence"}:
        try:
            result = InvestigationResult.model_validate_json(record.result_json)
        except Exception:
            result = None
    return InvestigationResponse(
        id=record.id,
        incident_id=record.incident_id,
        provider=record.provider,
        status=record.status,
        simulated=record.simulated,
        confidence=record.confidence,
        result=result,
        error_code=record.error_code,
        created_at=record.created_at,
    )


@api.get("/ai/status", response_model=ProviderStatusResponse, tags=["ai"])
async def ai_status() -> ProviderStatusResponse:
    provider = get_provider()
    return ProviderStatusResponse(**(await provider.status()).__dict__)


@api.post("/ai/test", response_model=ProviderStatusResponse, tags=["ai"])
async def ai_test() -> ProviderStatusResponse:
    provider = get_provider()
    try:
        return ProviderStatusResponse(**(await provider.test_connection()).__dict__)
    except AIProviderError as exc:
        raise HTTPException(status_code=503, detail={"code": exc.code, "message": str(exc)}) from exc


@api.get("/integrations/status", response_model=list[IntegrationStatusResponse], tags=["integrations"])
async def integrations_status() -> list[IntegrationStatusResponse]:
    statuses = await integration_statuses(settings)
    return [IntegrationStatusResponse(**status.__dict__) for status in statuses]


@api.post("/incidents/{incident_id}/investigations", response_model=InvestigationResponse, status_code=201, tags=["ai investigations"])
async def investigate_incident(incident_id: int, session: AsyncSession = Depends(get_session)) -> InvestigationResponse:
    row = (await session.execute(select(Incident, Service).join(Service).where(Incident.id == incident_id))).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident, service = row
    provider = get_provider()
    record = Investigation(
        incident_id=incident.id,
        provider=provider.name,
        status="running",
        simulated=provider.simulated,
    )
    session.add(record)
    await session.flush()
    if incident.state == IncidentState.DETECTED:
        validate_transition(incident.state, IncidentState.INVESTIGATING)
        incident.state = IncidentState.INVESTIGATING
    session.add(
        IncidentEvent(
            incident_id=incident.id,
            event_type="INVESTIGATION_STARTED",
            description=f"Investigation started with {provider.name}.",
            metadata_json=json.dumps({"provider": provider.name, "simulated": provider.simulated}),
        )
    )
    await session.commit()
    evidence = await build_investigation_input(session, incident, service)
    try:
        result = await provider.investigate(evidence)
        status_value = "completed"
        if result.confidence_estimate < settings.ai_confidence_threshold:
            status_value = "low_confidence"
            if incident.state == IncidentState.INVESTIGATING:
                validate_transition(incident.state, IncidentState.ESCALATED)
                incident.state = IncidentState.ESCALATED
                incident.escalation_status = "created"
            raise LowConfidenceInvestigationError("Investigation confidence is below the configured threshold.")
        record.status = status_value
        record.confidence = result.confidence_estimate
        record.result_json = result.model_dump_json()
        incident.probable_root_cause = result.probable_root_cause
        incident.recovery_recommendation = result.recommended_action
        session.add(
            IncidentEvent(
                incident_id=incident.id,
                event_type="INVESTIGATION_COMPLETED",
                description=result.summary,
                metadata_json=json.dumps({"provider": provider.name, "confidence": result.confidence_estimate}),
            )
        )
        if result.recommended_action == ESCALATE_TO_ADMINISTRATOR:
            # No recovery action can contain this incident, so hand it to an administrator rather than imply one can.
            await create_escalation(
                session,
                incident,
                f"Investigation recommends administrator escalation: {result.probable_root_cause}.",
                {"reason": "MANUAL_CONTAINMENT_REQUIRED", "evidence_references": result.evidence_references},
                result.reason_for_recommendation,
            )
    except LowConfidenceInvestigationError as exc:
        record.status = "low_confidence"
        record.error_code = exc.code
        record.result_json = result.model_dump_json() if "result" in locals() else "{}"
        session.add(
            IncidentEvent(
                incident_id=incident.id,
                event_type="ESCALATION_CREATED",
                description=str(exc),
                metadata_json=json.dumps({"reason": exc.code, "threshold": settings.ai_confidence_threshold}),
            )
        )
        await create_escalation(
            session,
            incident,
            str(exc),
            {"reason": exc.code, "threshold": settings.ai_confidence_threshold},
            "Administrator investigation is required before recovery.",
        )
    except AIProviderError as exc:
        record.status = "failed"
        record.error_code = exc.code
        if incident.state == IncidentState.INVESTIGATING:
            validate_transition(incident.state, IncidentState.ESCALATED)
            incident.state = IncidentState.ESCALATED
            incident.escalation_status = "created"
        session.add(
            IncidentEvent(
                incident_id=incident.id,
                event_type="ESCALATION_CREATED",
                description=str(exc),
                metadata_json=json.dumps({"reason": exc.code, "provider": provider.name}),
            )
        )
        await create_escalation(
            session,
            incident,
            str(exc),
            {"reason": exc.code, "provider": provider.name},
            "Review provider availability and investigate the incident manually.",
        )
    await session.commit()
    await session.refresh(record)
    return investigation_response(record)


@api.get("/incidents/{incident_id}/investigations", response_model=list[InvestigationResponse], tags=["ai investigations"])
async def list_investigations(incident_id: int, session: AsyncSession = Depends(get_session)) -> list[InvestigationResponse]:
    if await session.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    records = list((await session.scalars(select(Investigation).where(Investigation.incident_id == incident_id).order_by(Investigation.created_at.desc()))).all())
    return [investigation_response(record) for record in records]


@api.get("/recovery/actions", response_model=list[RecoveryActionResponse], tags=["recovery"])
async def recovery_actions() -> list[RecoveryActionResponse]:
    return [
        RecoveryActionResponse(
            action_id=action.action_id,
            description=action.description,
            required_permissions=list(action.required_permissions),
            risk=action.risk,
            timeout_seconds=action.timeout_seconds,
            allowed_parameters=sorted(action.allowed_parameters),
            preconditions=list(action.preconditions),
            handler=action.handler,
            rollback_strategy=action.rollback_strategy,
            verification_procedure=action.verification_procedure,
        )
        for action in ACTION_CATALOG.values()
    ]


@api.post("/incidents/{incident_id}/recovery/approve", response_model=IncidentResponse, tags=["recovery"])
async def approve_recovery(
    incident_id: int,
    payload: RecoveryRequest,
    x_demo_admin_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> IncidentResponse:
    require_demo_admin(x_demo_admin_token)
    row = (await session.execute(select(Incident, Service).join(Service).where(Incident.id == incident_id))).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident, service = row
    service_name = service.name
    try:
        action = get_action(payload.action_id)
    except PolicyRejected as exc:
        raise HTTPException(status_code=409, detail={"code": exc.code, "message": str(exc)}) from exc
    if action.risk == "low":
        raise HTTPException(status_code=409, detail="Low-risk actions do not require approval")
    if incident.state == IncidentState.ESCALATED:
        validate_transition(incident.state, IncidentState.INVESTIGATING)
        incident.state = IncidentState.INVESTIGATING
    if incident.state == IncidentState.INVESTIGATING:
        validate_transition(incident.state, IncidentState.AWAITING_APPROVAL)
        incident.state = IncidentState.AWAITING_APPROVAL
    try:
        validate_policy(incident, service, payload.action_id, payload.parameters)
    except PolicyRejected as exc:
        raise HTTPException(status_code=409, detail={"code": exc.code, "message": str(exc)}) from exc
    approval_id = str(uuid4())
    now = datetime.now(timezone.utc)
    session.add(
        RecoveryApproval(
            id=approval_id,
            incident_id=incident.id,
            action_id=action.action_id,
            parameters_hash=parameters_hash(payload.parameters),
            approver_principal="shared_operator",
            created_at=now,
            expires_at=now + timedelta(minutes=settings.recovery_approval_expiry_minutes),
        )
    )
    session.add(
        IncidentEvent(
            incident_id=incident.id,
            event_type="POLICY_DECISION",
            description=f"Administrator approved {payload.action_id}.",
            metadata_json=json.dumps({"action_id": payload.action_id, "parameters": payload.parameters, "approval_id": approval_id}),
        )
    )
    session.add(AuditEvent(event_type="recovery.approved", message=f"Approved {payload.action_id} for incident {incident.id} with approval {approval_id}", is_demo=incident.is_demo))
    await session.commit()
    return incident_response(incident, service_name)


@api.post("/incidents/{incident_id}/recovery", response_model=RecoveryExecutionResponse, status_code=201, tags=["recovery"])
async def recover_incident(
    incident_id: int,
    payload: RecoveryRequest,
    x_demo_admin_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> RecoveryExecutionResponse:
    require_demo_admin(x_demo_admin_token)
    row = (await session.execute(select(Incident, Service).join(Service).where(Incident.id == incident_id))).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident, service = row
    try:
        execution, _ = await execute_recovery(
            session, monitoring, incident, service, payload.action_id, payload.parameters, "shared_operator"
        )
    except PolicyRejected as exc:
        raise HTTPException(status_code=409, detail={"code": exc.code, "message": str(exc)}) from exc
    await session.refresh(execution)
    return recovery_execution_response(execution)


@api.get("/incidents/{incident_id}/recovery", response_model=list[RecoveryExecutionResponse], tags=["recovery"])
async def list_recovery_executions(incident_id: int, session: AsyncSession = Depends(get_session)) -> list[RecoveryExecutionResponse]:
    if await session.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    records = list((await session.scalars(select(RecoveryExecution).where(RecoveryExecution.incident_id == incident_id).order_by(RecoveryExecution.started_at.desc()))).all())
    return [recovery_execution_response(record) for record in records]


@api.get("/recovery/executions", response_model=list[RecoveryExecutionResponse], tags=["recovery"])
async def list_all_recovery_executions(session: AsyncSession = Depends(get_session)) -> list[RecoveryExecutionResponse]:
    records = list((await session.scalars(select(RecoveryExecution).order_by(RecoveryExecution.started_at.desc()))).all())
    return [recovery_execution_response(record) for record in records]


@api.get("/incidents/{incident_id}/verification", response_model=list[VerificationResponse], tags=["recovery"])
async def list_verifications(incident_id: int, session: AsyncSession = Depends(get_session)) -> list[VerificationResponse]:
    if await session.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    records = list((await session.scalars(select(VerificationAttempt).where(VerificationAttempt.incident_id == incident_id).order_by(VerificationAttempt.created_at.desc()))).all())
    return [verification_response(record) for record in records]


@api.get("/escalations", response_model=list[EscalationResponse], tags=["escalation"])
async def list_escalations(
    status_filter: str | None = Query(default=None, alias="status", pattern="^(pending|acknowledged|rejected)$"),
    session: AsyncSession = Depends(get_session),
) -> list[EscalationResponse]:
    """All escalations, newest first. Processed escalations stay listed as history; filter with ?status=pending."""
    records = list((await session.scalars(select(Escalation).order_by(Escalation.escalated_at.desc(), Escalation.id.desc()))).all())
    if status_filter is not None:
        records = [record for record in records if escalation_status(record) == status_filter]
    return [escalation_response(record) for record in records]


@api.get("/incidents/{incident_id}/escalation", response_model=list[EscalationResponse], tags=["escalation"])
async def incident_escalations(incident_id: int, session: AsyncSession = Depends(get_session)) -> list[EscalationResponse]:
    if await session.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    records = list((await session.scalars(select(Escalation).where(Escalation.incident_id == incident_id).order_by(Escalation.escalated_at.desc(), Escalation.id.desc()))).all())
    return [escalation_response(record) for record in records]


def _escalation_error(exc: Exception) -> HTTPException:
    if isinstance(exc, EscalationNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    return HTTPException(status_code=409, detail={"code": getattr(exc, "code", "ESCALATION_CONFLICT"), "message": str(exc)})


@api.post("/incidents/{incident_id}/acknowledge", response_model=EscalationResponse, tags=["escalation"])
async def acknowledge_incident(
    incident_id: int,
    administrator: str = Query(default="local-admin", min_length=1, max_length=120),
    escalation_id: int | None = Query(default=None, ge=1),
    x_demo_admin_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> EscalationResponse:
    """Acknowledge one escalation (``escalation_id``, or the incident's newest pending one). Idempotency: a second call is a 409."""
    require_demo_admin(x_demo_admin_token)
    try:
        escalation = await process_escalation(session, incident_id, escalation_id, STATUS_ACKNOWLEDGED, administrator)
    except (EscalationNotFound, EscalationConflict) as exc:
        await session.rollback()
        raise _escalation_error(exc) from exc
    await session.commit()
    return escalation_response(escalation)


@api.post("/incidents/{incident_id}/reject-recovery", response_model=EscalationResponse, tags=["escalation"])
async def reject_recovery(
    incident_id: int,
    reason: str = Query(default="Administrator rejected the proposed recovery action.", min_length=1, max_length=500),
    administrator: str = Query(default="local-admin", min_length=1, max_length=120),
    escalation_id: int | None = Query(default=None, ge=1),
    x_demo_admin_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> EscalationResponse:
    """Reject the proposed recovery of one escalation and record the decision.

    The escalation and the decision stay in history, unused approvals for the incident are revoked, and the incident is
    NOT resolved: it stays open for manual handling. An incident that was never escalated is escalated first.
    """
    require_demo_admin(x_demo_admin_token)
    incident = await session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        try:
            escalation = await process_escalation(session, incident_id, escalation_id, STATUS_REJECTED, administrator, reason)
        except EscalationNotFound:
            if escalation_id is not None:
                raise
            if incident.state == IncidentState.RESOLVED:
                raise EscalationConflict("The incident is already resolved, so there is no recovery to reject.", "INCIDENT_RESOLVED")
            created = await create_escalation(
                session,
                incident,
                reason,
                {"source": "administrator", "decision": "rejected"},
                "Investigate manually and select a separately approved safe action.",
            )
            await session.flush()
            escalation = await process_escalation(session, incident_id, created.id, STATUS_REJECTED, administrator, reason)
    except (EscalationNotFound, EscalationConflict) as exc:
        await session.rollback()
        raise _escalation_error(exc) from exc
    await session.commit()
    return escalation_response(escalation)

@api.post("/incidents/{incident_id}/under-investigation", response_model=IncidentResponse, tags=["escalation"])
async def mark_under_investigation(
    incident_id: int,
    x_demo_admin_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> IncidentResponse:
    require_demo_admin(x_demo_admin_token)
    row = (await session.execute(select(Incident, Service.name).join(Service).where(Incident.id == incident_id))).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident, service_name = row
    try:
        validate_transition(incident.state, IncidentState.INVESTIGATING)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    incident.state = IncidentState.INVESTIGATING
    session.add(AuditEvent(event_type="incident.under_investigation", message=f"Incident {incident.id} marked under investigation", is_demo=incident.is_demo))
    session.add(IncidentEvent(incident_id=incident.id, event_type="ADMIN_ACKNOWLEDGED", description="Administrator marked incident under investigation.", metadata_json="{}"))
    await session.commit()
    return incident_response(incident, service_name)


@api.post("/incidents/{incident_id}/recovery/retry", response_model=RecoveryExecutionResponse, status_code=201, tags=["recovery"])
async def retry_recovery(
    incident_id: int,
    payload: RecoveryRequest,
    x_demo_admin_token: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> RecoveryExecutionResponse:
    require_demo_admin(x_demo_admin_token)
    row = (await session.execute(select(Incident, Service).join(Service).where(Incident.id == incident_id))).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident, service = row
    if incident.state == IncidentState.ESCALATED:
        incident.state = IncidentState.INVESTIGATING
        await session.commit()
    try:
        execution, _ = await execute_recovery(session, monitoring, incident, service, payload.action_id, payload.parameters, "shared_operator")
    except PolicyRejected as exc:
        raise HTTPException(status_code=409, detail={"code": exc.code, "message": str(exc)}) from exc
    await session.refresh(execution)
    return recovery_execution_response(execution)


@api.get("/notifications", response_model=list[NotificationResponse], tags=["notifications"])
async def list_notifications(session: AsyncSession = Depends(get_session)) -> list[NotificationResponse]:
    records = list((await session.scalars(select(Notification).order_by(Notification.created_at.desc()).limit(100))).all())
    return [NotificationResponse.model_validate(record) for record in records]


def require_demo_admin(x_demo_admin_token: str | None) -> None:
    if settings.environment.lower() not in {"local", "demo", "test"} and settings.demo_admin_token == "local-demo-admin":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Administrative authentication is not configured for this environment",
        )
    if x_demo_admin_token != settings.demo_admin_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Demo administrator authorization required")


@api.get("/demo/scenarios", tags=["demo"])
async def demo_scenarios() -> dict[str, object]:
    return {"simulated": True, "scenarios": sorted(DEMO_SCENARIOS)}


@api.post("/demo/services/{service_id}/fault", tags=["demo"])
async def inject_fault(service_id: int, payload: DemoFaultRequest, x_demo_admin_token: str | None = Header(default=None), session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    require_demo_admin(x_demo_admin_token)
    if payload.scenario not in DEMO_SCENARIOS:
        raise HTTPException(status_code=422, detail="Unsupported demo scenario")
    service = await session.get(Service, service_id)
    if service is None or not service.simulation_status or service.environment != "demo":
        raise HTTPException(status_code=403, detail="Fault injection is restricted to isolated demo services")
    fault = await session.scalar(select(DemoFault).where(DemoFault.service_id == service_id))
    if fault is None:
        fault = DemoFault(service_id=service_id, scenario=payload.scenario)
        session.add(fault)
    else:
        fault.scenario = payload.scenario
    await session.commit()
    # Run the same health checks the monitor would, so the failure is detected now rather than after
    # `failure_threshold` monitoring intervals. Injecting "healthy" is a restore, which the monitor
    # (or the recovery workflow) handles, so no immediate check is run for it.
    health_checks_run = 0
    if payload.scenario != "healthy":
        for _ in range(max(1, service.failure_threshold)):
            await monitoring.check_service(service_id)
            health_checks_run += 1
    return {"service_id": service_id, "scenario": payload.scenario, "simulated": True, "health_checks_run": health_checks_run}


@api.post("/demo/services/{service_id}/reset", tags=["demo"])
async def reset_demo(service_id: int, x_demo_admin_token: str | None = Header(default=None), session: AsyncSession = Depends(get_session)) -> dict[str, object]:
    require_demo_admin(x_demo_admin_token)
    service = await session.get(Service, service_id)
    if service is None or not service.simulation_status or service.environment != "demo":
        raise HTTPException(status_code=403, detail="Reset is restricted to isolated demo services")
    fault = await session.scalar(select(DemoFault).where(DemoFault.service_id == service_id))
    if fault is None:
        session.add(DemoFault(service_id=service_id, scenario="healthy"))
    else:
        fault.scenario = "healthy"
    await session.commit()
    return {"service_id": service_id, "scenario": "healthy", "simulated": True}


app.include_router(api, prefix="/api/v1")
