from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.ai import InvestigationResult

class HealthResponse(BaseModel):
    status: str
    service: str
    environment: str
    mode: str = "DEMO"
    simulated: bool = True
    data_source: str = "local_simulation"
    database: str | None = None


class OperatingModeResponse(BaseModel):
    mode: str
    simulated: bool
    data_source: str
    external_integrations_available: bool


class ServiceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    environment: str = "demo"
    health_check_config: dict[str, Any] = {}
    health_check_timeout_seconds: float = Field(default=2.0, gt=0, le=60)
    failure_threshold: int = Field(default=2, ge=1, le=10)
    monitoring_interval_seconds: int = Field(default=30, ge=1, le=3600)
    simulation_status: bool = True


class ServiceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = None
    enabled: bool | None = None
    health_check_config: dict[str, Any] | None = None
    health_check_timeout_seconds: float | None = Field(default=None, gt=0, le=60)
    failure_threshold: int | None = Field(default=None, ge=1, le=10)
    monitoring_interval_seconds: int | None = Field(default=None, ge=1, le=3600)


class ServiceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    status: str
    environment: str
    health_check_config: dict[str, Any]
    health_check_timeout_seconds: float
    failure_threshold: int
    monitoring_interval_seconds: int
    consecutive_failure_count: int
    last_successful_check: datetime | None
    last_failed_check: datetime | None
    simulation_status: bool
    updated_at: datetime | None


class HealthCheckResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    service_id: int
    status: str
    response_time_ms: float
    observed_at: datetime | None
    error_message: str | None
    evidence: dict[str, Any]
    simulated: bool


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    service_id: int
    service_name: str
    incident_type: str
    severity: str
    state: str
    summary: str
    description: str
    diagnostic_evidence: dict[str, Any]
    probable_root_cause: str | None
    recovery_recommendation: str | None
    recovery_outcome: str | None
    verification_outcome: str | None
    escalation_status: str
    detection_timestamp: datetime | None
    resolution_timestamp: datetime | None
    is_demo: bool
    detection_rule: str = "health_check_failure"
    evidence_references: list[str] = []
    priority_score: float = 0
    priority_factors: dict[str, Any] = {}


class IncidentStateUpdate(BaseModel):
    target_state: str
    description: str = ""


class IncidentEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    event_type: str
    description: str
    metadata: dict[str, Any]
    created_at: datetime | None


class OverviewResponse(BaseModel):
    services: list[ServiceResponse]
    incidents: list[IncidentResponse]
    metrics: dict[str, int]
    seeded_demo_data: bool


class DemoFaultRequest(BaseModel):
    scenario: str


class DashboardStatsResponse(BaseModel):
    total_services: int
    healthy_services: int
    active_incidents: int
    resolved_incidents: int
    failed_checks_last_hour: int
    unhealthy_services: int = 0
    escalated_incidents: int = 0
    average_verified_recovery_seconds: float | None = None
    severity_distribution: dict[str, int] = {}
    recovery_activity: list[dict[str, int | str]] = []
    detection_counts: dict[str, int] = {}
    mean_time_to_detect_seconds: float | None = None
    recovery_success_rate: float | None = None


class ProviderStatusResponse(BaseModel):
    provider: str
    configured: bool
    connected: bool
    simulated: bool
    message: str


class IntegrationStatusResponse(BaseModel):
    name: str
    state: str
    configured: bool
    connected: bool
    simulated: bool
    message: str


class InvestigationResponse(BaseModel):
    id: int
    incident_id: int
    provider: str
    status: str
    simulated: bool
    confidence: float | None
    result: InvestigationResult | None = None
    error_code: str | None = None
    created_at: datetime | None = None


class RecoveryRequest(BaseModel):
    action_id: str = Field(min_length=1, max_length=80)
    parameters: dict[str, Any] = {}
    # Retained for wire compatibility; authorization is server-side.
    approved: bool = False


class RecoveryActionResponse(BaseModel):
    action_id: str
    description: str
    required_permissions: list[str]
    risk: str
    timeout_seconds: float
    allowed_parameters: list[str]
    preconditions: list[str]
    handler: str
    rollback_strategy: str
    verification_procedure: str


class RecoveryExecutionResponse(BaseModel):
    id: int
    incident_id: int
    service_id: int
    action_id: str
    parameters: dict[str, Any]
    status: str
    result: dict[str, Any]
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None


class VerificationResponse(BaseModel):
    id: int
    incident_id: int
    execution_id: int | None
    outcome: str
    successful_checks: int
    required_checks: int
    evidence: dict[str, Any]
    created_at: datetime | None


class EscalationResponse(BaseModel):
    id: int
    incident_id: int
    reason: str
    severity: str
    evidence: dict[str, Any]
    ai_findings: dict[str, Any]
    attempted_actions: list[Any]
    policy_decisions: list[Any]
    recommended_next_steps: str
    acknowledged: bool
    assigned_administrator: str | None
    escalated_at: datetime | None
    acknowledged_at: datetime | None
    # Derived from persisted columns: pending, acknowledged, or rejected (a rejected recovery also keeps its reason).
    status: str = "pending"
    rejection_reason: str | None = None


class NotificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int | None
    kind: str
    severity: str
    service_name: str
    reason: str
    dashboard_link: str
    read: bool
    created_at: datetime | None


class ErrorResponse(BaseModel):
    error: dict[str, object]


class InfrastructureResourceResponse(BaseModel):
    id: int
    resource_key: str
    name: str
    resource_type: str
    status: str
    environment: str
    configuration: dict[str, Any]
    metadata: dict[str, Any]
    parent_resource_id: int | None
    simulated: bool
    created_at: datetime | None
    updated_at: datetime | None


class TelemetryEventResponse(BaseModel):
    event_id: str
    resource_id: int
    resource_key: str
    category: str
    event_type: str
    severity: str
    summary: str
    observed_at: datetime
    source: str
    metadata: dict[str, Any]
    correlation_id: str | None
    simulated: bool


class SimulationStateResponse(BaseModel):
    scenario: str
    status: str
    seed: int
    tick_count: int
    started_at: datetime | None
    stopped_at: datetime | None


class SimulationStartRequest(BaseModel):
    scenario: str = Field(default="baseline", min_length=1, max_length=64)
    seed: int = Field(default=1, ge=0, le=2_147_483_647)
    event_count: int = Field(default=10, ge=1, le=100)
