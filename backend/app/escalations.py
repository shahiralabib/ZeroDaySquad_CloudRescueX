"""Escalation lifecycle: an escalation is pending until an administrator acknowledges it or rejects its recovery.

The outcome is persisted on the escalation row itself, using columns that already exist (no migration), so
databases created by earlier migrations keep working:

* acknowledged / acknowledged_at / assigned_administrator record that an administrator handled the escalation;
* a rejection additionally appends a ``recovery_rejected`` decision (with the reason) to ``policy_decisions_json``.

``escalation_status`` derives ``pending`` / ``acknowledged`` / ``rejected`` from those columns. Processing never
deletes the record, never changes the incident's state, and never touches a service's health.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AuditEvent, Escalation, IncidentEvent, RecoveryApproval

STATUS_PENDING = "pending"
STATUS_ACKNOWLEDGED = "acknowledged"
STATUS_REJECTED = "rejected"
REJECTION_DECISION = "recovery_rejected"


class EscalationNotFound(LookupError):
    pass


class EscalationConflict(Exception):
    def __init__(self, message: str, code: str = "ESCALATION_ALREADY_PROCESSED"):
        super().__init__(message)
        self.code = code


def _decisions(record: Escalation) -> list[Any]:
    try:
        parsed = json.loads(record.policy_decisions_json or "[]")
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def rejection_of(record: Escalation) -> dict[str, Any] | None:
    """The recorded recovery rejection for this escalation, if an administrator rejected it."""
    for decision in reversed(_decisions(record)):
        if isinstance(decision, dict) and decision.get("decision") == REJECTION_DECISION:
            return decision
    return None


def escalation_status(record: Escalation) -> str:
    if rejection_of(record) is not None:
        return STATUS_REJECTED
    return STATUS_ACKNOWLEDGED if record.acknowledged else STATUS_PENDING


async def process_escalation(
    session: AsyncSession,
    incident_id: int,
    escalation_id: int | None,
    decision: str,
    administrator: str,
    reason: str | None = None,
) -> Escalation:
    """Acknowledge an escalation, or reject its proposed recovery. Each escalation can be processed exactly once.

    Targets ``escalation_id`` when given, otherwise the incident's newest pending escalation. The caller commits.
    """
    if decision not in (STATUS_ACKNOWLEDGED, STATUS_REJECTED):
        raise ValueError(f"Unsupported escalation decision: {decision}")
    if escalation_id is not None:
        record = await session.get(Escalation, escalation_id)
        if record is None or record.incident_id != incident_id:
            raise EscalationNotFound("Escalation not found for this incident")
    else:
        record = await session.scalar(
            select(Escalation)
            .where(Escalation.incident_id == incident_id, Escalation.acknowledged.is_(False))
            .order_by(Escalation.id.desc())
        )
        if record is None:
            if await session.scalar(select(Escalation.id).where(Escalation.incident_id == incident_id).limit(1)) is None:
                raise EscalationNotFound("Escalation not found")
            raise EscalationConflict("This incident has no pending escalation: every escalation was already processed.", "NO_PENDING_ESCALATION")
    if record.acknowledged:
        raise EscalationConflict(f"Escalation {record.id} was already {escalation_status(record)}.")

    now = datetime.now(timezone.utc)
    values: dict[str, Any] = {"acknowledged": True, "acknowledged_at": now, "assigned_administrator": administrator}
    rejection: dict[str, Any] | None = None
    if decision == STATUS_REJECTED:
        rejection = {
            "decision": REJECTION_DECISION,
            "reason": reason or "Administrator rejected the proposed recovery action.",
            "decided_by": administrator,
            "decided_at": now.isoformat(),
        }
        values["policy_decisions_json"] = json.dumps([*_decisions(record), rejection])
    # Atomic claim: of two simultaneous requests for the same escalation, only one can flip it from pending.
    claimed = await session.execute(
        update(Escalation)
        .execution_options(synchronize_session=False)
        .where(Escalation.id == record.id, Escalation.acknowledged.is_(False))
        .values(**values)
    )
    if claimed.rowcount != 1:
        raise EscalationConflict(f"Escalation {record.id} was already processed by another request.")
    await session.refresh(record)

    if rejection is None:
        session.add(AuditEvent(event_type="escalation.acknowledged", message=f"Escalation {record.id} acknowledged by {administrator}", is_demo=True))
        session.add(IncidentEvent(
            incident_id=incident_id,
            event_type="ADMIN_ACKNOWLEDGED",
            description=f"Administrator {administrator} acknowledged escalation.",
            metadata_json=json.dumps({"administrator": administrator, "escalation_id": record.id}),
        ))
        return record

    # A rejected recovery must not stay executable: revoke approvals that were granted but not yet used.
    revoked = await session.execute(
        update(RecoveryApproval)
        .execution_options(synchronize_session=False)
        .where(
            RecoveryApproval.incident_id == incident_id,
            RecoveryApproval.consumed_at.is_(None),
            RecoveryApproval.revoked.is_(False),
        )
        .values(revoked=True)
    )
    session.add(AuditEvent(event_type="recovery.rejected", message=f"Recovery rejected for incident {incident_id} (escalation {record.id}) by {administrator}: {rejection['reason']}", is_demo=True))
    session.add(IncidentEvent(
        incident_id=incident_id,
        event_type="POLICY_DECISION",
        description=f"Administrator {administrator} rejected the proposed recovery: {rejection['reason']}",
        metadata_json=json.dumps({
            "decision": REJECTION_DECISION,
            "escalation_id": record.id,
            "administrator": administrator,
            "approvals_revoked": revoked.rowcount,
        }),
    ))
    return record
