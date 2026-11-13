from __future__ import annotations

from collections.abc import AsyncGenerator
import json
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.config import get_settings


class Base(DeclarativeBase):
    pass


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="healthy")
    environment: Mapped[str] = mapped_column(String(32), default="demo")
    health_check_config: Mapped[str] = mapped_column(Text, default="{}")
    health_check_timeout_seconds: Mapped[float] = mapped_column(Float, default=2.0)
    failure_threshold: Mapped[int] = mapped_column(Integer, default=2)
    monitoring_interval_seconds: Mapped[int] = mapped_column(Integer, default=30)
    consecutive_failure_count: Mapped[int] = mapped_column(Integer, default=0)
    last_successful_check: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_failed_check: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    simulation_status: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
    incidents: Mapped[List["Incident"]] = relationship(back_populates="service")
    health_checks: Mapped[List["HealthCheck"]] = relationship(back_populates="service")


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"))
    incident_type: Mapped[str] = mapped_column(String(64), default="service_unavailable")
    severity: Mapped[str] = mapped_column(String(16))
    state: Mapped[str] = mapped_column(String(32), default="DETECTED")
    summary: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    diagnostic_evidence: Mapped[str] = mapped_column(Text, default="{}")
    probable_root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recovery_recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recovery_outcome: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    verification_outcome: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    escalation_status: Mapped[str] = mapped_column(String(32), default="not_escalated")
    detection_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolution_timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deduplication_key: Mapped[str] = mapped_column(String(160), index=True)
    detection_rule: Mapped[str] = mapped_column(String(120), default="health_check_failure", index=True)
    evidence_references_json: Mapped[str] = mapped_column(Text, default="[]")
    priority_score: Mapped[float] = mapped_column(Float, default=0)
    priority_factors_json: Mapped[str] = mapped_column(Text, default="{}")
    is_demo: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
    service: Mapped[Service] = relationship(back_populates="incidents")
    timeline: Mapped[List["IncidentEvent"]] = relationship(back_populates="incident", order_by="IncidentEvent.created_at")
    recovery_approvals: Mapped[List["RecoveryApproval"]] = relationship(back_populates="incident")


class HealthCheck(Base):
    __tablename__ = "health_checks"

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    status: Mapped[str] = mapped_column(String(32))
    response_time_ms: Mapped[float] = mapped_column(Float)
    observed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, default="{}")
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    service: Mapped[Service] = relationship(back_populates="health_checks")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
    incident: Mapped[Incident] = relationship(back_populates="timeline")


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    provider: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DemoFault(Base):
    __tablename__ = "demo_faults"

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), unique=True)
    scenario: Mapped[str] = mapped_column(String(64), default="healthy")
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(String(80))
    message: Mapped[str] = mapped_column(Text)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RecoveryExecution(Base):
    __tablename__ = "recovery_executions"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), index=True)
    action_id: Mapped[str] = mapped_column(String(80))
    parameters_json: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(32), default="started")
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RecoveryApproval(Base):
    __tablename__ = "recovery_approvals"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    action_id: Mapped[str] = mapped_column(String(80))
    parameters_hash: Mapped[str] = mapped_column(String(64), index=True)
    approver_principal: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    incident: Mapped[Incident] = relationship(back_populates="recovery_approvals")


class VerificationAttempt(Base):
    __tablename__ = "verification_attempts"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    execution_id: Mapped[Optional[int]] = mapped_column(ForeignKey("recovery_executions.id"), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32))
    successful_checks: Mapped[int] = mapped_column(Integer, default=0)
    required_checks: Mapped[int] = mapped_column(Integer, default=1)
    evidence_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Escalation(Base):
    __tablename__ = "escalations"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    reason: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    evidence_json: Mapped[str] = mapped_column(Text, default="{}")
    ai_findings_json: Mapped[str] = mapped_column(Text, default="{}")
    attempted_actions_json: Mapped[str] = mapped_column(Text, default="[]")
    policy_decisions_json: Mapped[str] = mapped_column(Text, default="[]")
    recommended_next_steps: Mapped[str] = mapped_column(Text, default="")
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    assigned_administrator: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    escalated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[Optional[int]] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    service_name: Mapped[str] = mapped_column(String(120))
    reason: Mapped[str] = mapped_column(Text)
    dashboard_link: Mapped[str] = mapped_column(String(240))
    deduplication_key: Mapped[str] = mapped_column(String(200), index=True)
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())


class InfrastructureResource(Base):
    __tablename__ = "infrastructure_resources"

    id: Mapped[int] = mapped_column(primary_key=True)
    resource_key: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    resource_type: Mapped[str] = mapped_column(String(40), index=True)
    status: Mapped[str] = mapped_column(String(32), default="healthy")
    environment: Mapped[str] = mapped_column(String(32), default="local_simulation")
    configuration_json: Mapped[str] = mapped_column(Text, default="{}")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    parent_resource_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("infrastructure_resources.id"), nullable=True, index=True
    )
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    parent: Mapped[Optional["InfrastructureResource"]] = relationship(
        remote_side=[id], back_populates="children"
    )
    children: Mapped[List["InfrastructureResource"]] = relationship(back_populates="parent")
    telemetry_events: Mapped[List["TelemetryEvent"]] = relationship(back_populates="resource")


class SimulationState(Base):
    __tablename__ = "simulation_states"

    id: Mapped[int] = mapped_column(primary_key=True)
    scenario: Mapped[str] = mapped_column(String(64), default="baseline")
    status: Mapped[str] = mapped_column(String(24), default="stopped")
    seed: Mapped[int] = mapped_column(Integer, default=1)
    tick_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    stopped_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    resource_id: Mapped[int] = mapped_column(ForeignKey("infrastructure_resources.id"), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    summary: Mapped[str] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(32), default="local_simulation")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    correlation_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    resource: Mapped[InfrastructureResource] = relationship(back_populates="telemetry_events")


settings = get_settings()
engine = create_async_engine(
    settings.database_url,
    echo=False,
    connect_args={"timeout": 30} if settings.database_url.startswith("sqlite") else {},
)
session_factory = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with session_factory() as session:
        yield session


async def init_db() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def seed_demo_data() -> None:
    if not settings.seed_demo_data:
        return
    async with session_factory() as session:
        service_count = await session.scalar(func.count(Service.id))
        if service_count:
            return
        services = [
            Service(name="Checkout API", status="healthy", environment="demo", simulation_status=True),
            Service(name="Payments Worker", status="degraded", environment="demo", simulation_status=True),
            Service(name="Customer Portal", status="healthy", environment="demo", simulation_status=True),
        ]
        session.add_all(services)
        await session.flush()
        seeded_incident = Incident(
            service_id=services[1].id,
            severity="high",
            state="INVESTIGATING",
            incident_type="dependency_unavailable",
            summary="Dependency timeout detected in payment processing",
            description="The simulated payment dependency is unavailable.",
            diagnostic_evidence=json.dumps({"source": "seed", "simulated": True}),
            deduplication_key="seed-payments-dependency",
            # Set explicitly: migration 0002 made this column NOT NULL without a database default,
            # so relying on the model's server_default fails on a freshly migrated database.
            detection_timestamp=datetime.now(timezone.utc),
            is_demo=True,
        )
        session.add(seeded_incident)
        await session.flush()
        session.add(
            IncidentEvent(
                incident_id=seeded_incident.id,
                event_type="DETECTION",
                description=seeded_incident.summary,
                metadata_json=json.dumps({"source": "seed", "simulated": True}),
            )
        )
        session.add_all(
            [
                DemoFault(service_id=services[0].id, scenario="healthy"),
                DemoFault(service_id=services[1].id, scenario="dependency_unavailable"),
                DemoFault(service_id=services[2].id, scenario="healthy"),
            ]
        )
        session.add(
            AuditEvent(
                event_type="demo.seeded",
                message="Seeded demonstration services and incident",
                is_demo=True,
            )
        )
        await session.commit()
