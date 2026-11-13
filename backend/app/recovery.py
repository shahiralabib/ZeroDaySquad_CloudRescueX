import asyncio
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import (
    AuditEvent,
    DemoFault,
    Escalation,
    Incident,
    IncidentEvent,
    InfrastructureResource,
    Notification,
    RecoveryApproval,
    RecoveryExecution,
    Service,
    TelemetryEvent,
    VerificationAttempt,
)
from app.domain import IncidentState, validate_transition
from app.monitoring import HEALTH_CHECK_RULE, MonitoringEngine
from app.remediation import ACTION_REMEDIATES, DETECTION_RULE_CATEGORY, OUTAGE_FAULT_CATEGORY, action_addresses
from app.notifications import LocalNotificationProvider


@dataclass(frozen=True)
class RecoveryAction:
    action_id: str
    description: str
    required_permissions: tuple[str, ...]
    risk: str
    timeout_seconds: float
    allowed_parameters: frozenset[str]
    preconditions: tuple[str, ...]
    handler: str
    rollback_strategy: str
    verification_procedure: str


ACTION_CATALOG: dict[str, RecoveryAction] = {
    "restart_demo_application": RecoveryAction(
        "restart_demo_application", "Restart isolated demo application", ("recovery:execute",), "low", 5, frozenset(), ("isolated_demo_service",), "_execute_demo_action", "Restore the prior demo fault if verification fails.", "Run two independent health checks."
    ),
    "restore_known_good_configuration": RecoveryAction(
        "restore_known_good_configuration", "Restore known-good application configuration", ("recovery:execute",), "medium", 5, frozenset(), ("isolated_demo_service",), "_execute_demo_action", "Restore the prior demo fault if verification fails.", "Run two independent health checks."
    ),
    "restore_demo_dependency": RecoveryAction(
        "restore_demo_dependency", "Restore simulated dependency availability", ("recovery:execute",), "low", 5, frozenset(), ("isolated_demo_service",), "_execute_demo_action", "Restore the prior demo fault if verification fails.", "Run two independent health checks."
    ),
    "scale_demo_application": RecoveryAction(
        "scale_demo_application", "Scale simulated application instances from zero to one", ("recovery:execute",), "medium", 5, frozenset({"instances"}), ("isolated_demo_service", "instances_equals_one"), "_execute_demo_action", "Restore the prior demo instance count.", "Run two independent health checks."
    ),
    "reset_demo_environment": RecoveryAction(
        "reset_demo_environment", "Reset isolated demo environment", ("recovery:execute",), "high", 5, frozenset(), ("isolated_demo_service",), "_execute_demo_action", "No automatic rollback; administrator review is required.", "Run two independent health checks."
    ),
}


# Fault categories, per-action remediation and resource-type rules live in app/remediation.py so the AI\n# recommendation and this module can never disagree.


def incident_fault_category(incident: Incident) -> str | None:
    """The kind of fault an incident represents, or None if unknown (nothing is then allowed to verify it)."""
    if incident.detection_rule == HEALTH_CHECK_RULE:
        return OUTAGE_FAULT_CATEGORY.get(incident.incident_type)
    return DETECTION_RULE_CATEGORY.get(incident.detection_rule)


def action_addresses_incident(action_id: str, incident: Incident, resource: InfrastructureResource | None = None) -> bool:
    """True if the action remediates this incident's kind of fault and can act on the incident's own asset."""
    category = incident_fault_category(incident)
    if incident.detection_rule == HEALTH_CHECK_RULE:
        return action_addresses(action_id, category, check_resource=False)
    return resource is not None and action_addresses(action_id, category, resource.resource_type)

async def affected_resource(session: AsyncSession, incident: Incident, *, refresh: bool = False) -> InfrastructureResource | None:
    """The simulated asset a telemetry incident is about (None for outage incidents or when it cannot be determined)."""
    if incident.detection_rule == HEALTH_CHECK_RULE:
        return None
    try:
        evidence = json.loads(incident.diagnostic_evidence or "{}")
    except json.JSONDecodeError:
        return None
    if not isinstance(evidence, dict):
        return None
    resource_key = evidence.get("resource_key")
    if not resource_key and evidence.get("event_id"):  # incidents recorded before the asset was stored in the evidence
        resource_key = await session.scalar(
            select(InfrastructureResource.resource_key)
            .join(TelemetryEvent, TelemetryEvent.resource_id == InfrastructureResource.id)
            .where(TelemetryEvent.event_id == evidence["event_id"])
        )
    if not resource_key:
        return None
    query = select(InfrastructureResource).where(InfrastructureResource.resource_key == resource_key)
    if refresh:
        query = query.execution_options(populate_existing=True)
    return await session.scalar(query)


# Rejections that are an expected outcome of the normal workflow (an approval has not been granted yet, the action does
# not fit this incident, the incident is not in a state that allows recovery, the work is already done or in progress).
# They are refused without escalating the incident to an administrator. Any other code, including unknown or future
# ones, is a hard rejection that does escalate, so a new code is never silently treated as routine.
SOFT_REJECTION_CODES = frozenset(
    {
        "APPROVAL_REQUIRED",
        "ACTION_NOT_APPLICABLE",
        "INVALID_INCIDENT_STATE",
        "DUPLICATE_EXECUTION",
        "INCIDENT_BUSY",
    }
)


class PolicyRejected(ValueError):
    """A recovery request refused by policy.

    ``escalates`` tells callers whether the rejection needs an administrator (hard) or is routine (soft). It defaults from
    the code (see ``SOFT_REJECTION_CODES``) and can be set explicitly. Existing callers do not read it yet: recovery still
    escalates every rejection until a later task acts on this distinction.
    """

    def __init__(self, message: str, code: str = "POLICY_REJECTED", escalates: bool | None = None):
        super().__init__(message)
        self.code = code
        self.escalates = (code not in SOFT_REJECTION_CODES) if escalates is None else escalates


def get_action(action_id: str) -> RecoveryAction:
    action = ACTION_CATALOG.get(action_id)
    if action is None:
        raise PolicyRejected("Unknown recovery action.", "UNKNOWN_ACTION")
    return action


def parameters_hash(parameters: dict[str, Any]) -> str:
    normalized = json.dumps(parameters, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_policy(incident: Incident, service: Service, action_id: str, parameters: dict[str, Any]) -> RecoveryAction:
    action = get_action(action_id)
    if incident.state in {IncidentState.RESOLVED, IncidentState.ESCALATED, IncidentState.FAILED}:
        raise PolicyRejected("Incident is not eligible for recovery.", "INVALID_INCIDENT_STATE")
    if not service.simulation_status or service.environment != "demo":
        raise PolicyRejected("Recovery is restricted to isolated demo services.", "UNSAFE_TARGET")
    evidence = incident.diagnostic_evidence and incident.diagnostic_evidence != "{}"
    if not evidence:
        raise PolicyRejected("Required diagnostic evidence is missing.", "MISSING_EVIDENCE")
    if set(parameters) != set(action.allowed_parameters):
        raise PolicyRejected("Action parameters are invalid.", "INVALID_PARAMETERS")
    if "instances" in parameters and (not isinstance(parameters["instances"], int) or parameters["instances"] != 1):
        raise PolicyRejected("instances must be exactly 1.", "INVALID_PARAMETERS")
    return action


async def consume_approval(
    session: AsyncSession,
    incident: Incident,
    action: RecoveryAction,
    parameters: dict[str, Any],
    principal: str,
) -> None:
    now = datetime.now(timezone.utc)
    approval = await session.scalar(
        select(RecoveryApproval)
        .where(
            RecoveryApproval.incident_id == incident.id,
            RecoveryApproval.action_id == action.action_id,
            RecoveryApproval.parameters_hash == parameters_hash(parameters),
            RecoveryApproval.approver_principal == principal,
            RecoveryApproval.revoked.is_(False),
            RecoveryApproval.consumed_at.is_(None),
            RecoveryApproval.expires_at > now,
        )
        .order_by(RecoveryApproval.created_at.desc())
    )
    if approval is None:
        raise PolicyRejected("A valid administrator approval is required for this action.", "APPROVAL_REQUIRED")
    claimed = await session.execute(
        update(RecoveryApproval)
        .execution_options(synchronize_session=False)
        .where(
            RecoveryApproval.id == approval.id,
            RecoveryApproval.revoked.is_(False),
            RecoveryApproval.consumed_at.is_(None),
            RecoveryApproval.expires_at > now,
        )
        .values(consumed_at=now)
    )
    if claimed.rowcount != 1:
        raise PolicyRejected("A valid administrator approval is required for this action.", "APPROVAL_REQUIRED")


async def create_escalation(
    session: AsyncSession,
    incident: Incident,
    reason: str,
    evidence: dict[str, Any],
    next_steps: str,
) -> Escalation:
    existing = await session.scalar(
        select(Escalation).where(Escalation.incident_id == incident.id, Escalation.acknowledged.is_(False))
    )
    if existing:
        # An open escalation must still leave the incident escalated (for example after a failed verification).
        if incident.state not in {IncidentState.ESCALATED, IncidentState.RESOLVED}:
            validate_transition(incident.state, IncidentState.ESCALATED)
            incident.state = IncidentState.ESCALATED
            incident.escalation_status = "created"
        return existing
    if incident.state not in {IncidentState.ESCALATED, IncidentState.RESOLVED}:
        validate_transition(incident.state, IncidentState.ESCALATED)
        incident.state = IncidentState.ESCALATED
    incident.escalation_status = "created"
    escalation = Escalation(
        incident_id=incident.id,
        reason=reason,
        severity=incident.severity,
        evidence_json=json.dumps(evidence),
        ai_findings_json=json.dumps({"probable_root_cause": incident.probable_root_cause}),
        recommended_next_steps=next_steps,
    )
    session.add(escalation)
    await session.flush()
    service = await session.get(Service, incident.service_id)
    if service:
        await LocalNotificationProvider().create_escalation_notification(
            session,
            incident_id=incident.id,
            severity=incident.severity,
            service_name=service.name,
            reason=reason,
        )
    session.add(
        IncidentEvent(
            incident_id=incident.id,
            event_type="ESCALATION_CREATED",
            description=reason,
            metadata_json=json.dumps({"reason": reason, "next_steps": next_steps}),
        )
    )
    return escalation


async def execute_recovery(
    session: AsyncSession,
    monitoring: MonitoringEngine,
    incident: Incident,
    service: Service,
    action_id: str,
    parameters: dict[str, Any],
    principal: str,
) -> tuple[RecoveryExecution, VerificationAttempt | None]:
    duplicate = await session.scalar(
        select(RecoveryExecution).where(
            RecoveryExecution.incident_id == incident.id,
            RecoveryExecution.action_id == action_id,
            RecoveryExecution.status.in_(["running", "completed"]),
        )
    )
    if duplicate:
        raise PolicyRejected("This recovery action has already been executed for the incident.", "DUPLICATE_EXECUTION")
    try:
        action = validate_policy(incident, service, action_id, parameters)
        if action.risk in {"medium", "high"}:
            await consume_approval(session, incident, action, parameters, principal)
    except PolicyRejected as exc:
        await create_escalation(session, incident, str(exc), {"code": exc.code, "action_id": action_id}, "Administrator review required.")
        session.add(AuditEvent(event_type="recovery.policy_rejected", message=str(exc), is_demo=service.simulation_status))
        await session.commit()
        raise
    if incident.state == IncidentState.DETECTED:
        validate_transition(incident.state, IncidentState.INVESTIGATING)
        incident.state = IncidentState.INVESTIGATING
    if incident.state in {IncidentState.INVESTIGATING, IncidentState.AWAITING_APPROVAL}:
        validate_transition(incident.state, IncidentState.RECOVERING)
        incident.state = IncidentState.RECOVERING
    execution = RecoveryExecution(
        incident_id=incident.id,
        service_id=service.id,
        action_id=action.action_id,
        parameters_json=json.dumps(parameters),
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    session.add(execution)
    await session.flush()
    session.add(IncidentEvent(incident_id=incident.id, event_type="RECOVERY_STARTED", description=action.description, metadata_json=json.dumps({"action_id": action.action_id, "parameters": parameters})))
    await session.commit()
    try:
        await asyncio.wait_for(_apply_action(session, service, incident, action.action_id, parameters), timeout=action.timeout_seconds)
        execution.status = "completed"
        execution.result_json = json.dumps({"executed": True, "simulated": True})
    except asyncio.TimeoutError:
        execution.status = "failed"
        execution.error_message = "Recovery action timed out."
    except Exception as exc:
        execution.status = "failed"
        execution.error_message = str(exc)
    execution.completed_at = datetime.now(timezone.utc)
    incident.recovery_outcome = execution.status
    session.add(IncidentEvent(incident_id=incident.id, event_type="RECOVERY_COMPLETED", description=execution.error_message or "Recovery action completed; independent verification required.", metadata_json=json.dumps({"execution_id": execution.id, "status": execution.status})))
    await session.commit()
    if execution.status != "completed":
        await create_escalation(session, incident, "Recovery execution failed.", {"execution_id": execution.id, "error": execution.error_message}, "Administrator review and an authorized retry may be required.")
        await session.commit()
        return execution, None
    verification = await verify_recovery(session, monitoring, incident, service, execution)
    return execution, verification


async def _apply_action(session: AsyncSession, service: Service, incident: Incident, action_id: str, parameters: dict[str, Any]) -> None:
    """Apply an action's simulated effect. It only changes the state of the fault it actually remediates."""
    if incident.detection_rule == HEALTH_CHECK_RULE:
        await _execute_demo_action(session, service, action_id, parameters)
    else:
        await _apply_resource_effect(session, incident, action_id, parameters)


async def _execute_demo_action(session: AsyncSession, service: Service, action_id: str, parameters: dict[str, Any]) -> None:
    """Service-level effect for outage incidents: clear the injected fault only if this action remediates that kind of fault."""
    fault = await session.scalar(select(DemoFault).where(DemoFault.service_id == service.id))
    category = OUTAGE_FAULT_CATEGORY.get(fault.scenario) if fault is not None else None
    if fault is not None and category in ACTION_REMEDIATES.get(action_id, frozenset()):
        fault.scenario = "healthy"
        service.status = "healthy"
        service.consecutive_failure_count = 0
    await session.flush()


async def _apply_resource_effect(session: AsyncSession, incident: Incident, action_id: str, parameters: dict[str, Any]) -> None:
    """Effect for telemetry incidents: restore only the incident's own asset, and only if the action addresses its fault."""
    resource = await affected_resource(session, incident)
    if resource is None or not action_addresses_incident(action_id, incident, resource):
        return
    resource.status = "healthy"
    if action_id == "restore_known_good_configuration":
        resource.configuration_json = json.dumps({"managed_by": "local_simulation", "configuration": "known_good"})
    elif action_id == "reset_demo_environment":
        resource.configuration_json = json.dumps({"managed_by": "local_simulation", "configuration": "baseline"})
    elif action_id == "scale_demo_application" and resource.resource_type == "web_server":
        resource.metadata_json = json.dumps({"source": "local_simulation", "synthetic": True, "instances": parameters["instances"]})
    await session.flush()


async def verify_recovery(
    session: AsyncSession,
    monitoring: MonitoringEngine,
    incident: Incident,
    service: Service,
    execution: RecoveryExecution,
    required_checks: int = 2,
) -> VerificationAttempt:
    if incident.state != IncidentState.VERIFYING:
        validate_transition(incident.state, IncidentState.VERIFYING)
        incident.state = IncidentState.VERIFYING
    successful = 0
    evidence: list[dict[str, Any]] = []
    is_outage = incident.detection_rule == HEALTH_CHECK_RULE
    fault_category = incident_fault_category(incident)
    initial_asset = None if is_outage else await affected_resource(session, incident)
    addresses_fault = action_addresses_incident(execution.action_id, incident, initial_asset)
    for _ in range(required_checks):
        # Outage incidents are verified by a real health check of the service; telemetry incidents by
        # re-reading the incident's own asset from the database. Either way the action must address the fault.
        health_check = await monitoring.check_service_in_session(session, service.id) if is_outage else None
        asset = None if is_outage else await affected_resource(session, incident, refresh=True)
        resources = list((await session.scalars(select(InfrastructureResource))).all())
        state_ok = health_check.status == "healthy" if health_check is not None else (asset is not None and asset.status == "healthy")
        evidence.append(
            {
                "health_check_id": health_check.id if health_check is not None else None,
                "status": health_check.status if health_check is not None else (asset.status if asset is not None else "unknown"),
                "error": health_check.error_message if health_check is not None else None,
                "fault_category": fault_category,
                "action_addresses_fault": addresses_fault,
                "affected_resource": asset.resource_key if asset is not None else None,
                "affected_resource_type": asset.resource_type if asset is not None else None,
                "affected_resource_healthy": (asset.status == "healthy") if asset is not None else None,
                "resource_state": {resource.resource_key: resource.status for resource in resources},
                "resources_healthy": state_ok,
            }
        )
        if addresses_fault and state_ok:
            successful += 1
        else:
            break
    outcome = "VERIFIED_SUCCESS" if successful == required_checks else "VERIFICATION_FAILED"
    attempt = VerificationAttempt(
        incident_id=incident.id,
        execution_id=execution.id,
        outcome=outcome,
        successful_checks=successful,
        required_checks=required_checks,
        evidence_json=json.dumps(evidence),
    )
    session.add(attempt)
    incident.verification_outcome = outcome
    if outcome == "VERIFIED_SUCCESS":
        validate_transition(incident.state, IncidentState.RESOLVED)
        incident.state = IncidentState.RESOLVED
        incident.resolution_timestamp = datetime.now(timezone.utc)
        session.add(IncidentEvent(incident_id=incident.id, event_type="RESOLUTION", description="Incident resolved after independent verification.", metadata_json=json.dumps({"verification": outcome})))
    else:
        await create_escalation(session, incident, "Independent recovery verification failed.", {"checks": evidence}, "Administrator review and a safe retry may be required.")
    session.add(IncidentEvent(incident_id=incident.id, event_type="VERIFICATION_COMPLETED", description=outcome, metadata_json=json.dumps({"successful_checks": successful, "required_checks": required_checks})))
    await session.commit()
    await session.refresh(attempt)
    return attempt
