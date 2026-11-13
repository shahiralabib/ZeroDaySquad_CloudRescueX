"""Incident state transitions that are validated, recorded and (optionally) claimed atomically.

This module only adds helpers. It does not change the state machine in ``app.domain`` (``ALLOWED_TRANSITIONS`` is still
the single source of truth) and existing code that assigns ``incident.state`` directly keeps working until later tasks
adopt these helpers.

* ``transition_incident`` validates one transition, applies it to the loaded incident and records one ``IncidentEvent``
  and one ``AuditEvent``.
* ``claim_state`` does the same, but first wins the transition with a single conditional ``UPDATE ... WHERE state IN (...)``.
  Of any number of concurrent callers only one can succeed; the others get ``StateClaimConflict`` and record nothing.

Neither helper commits: the caller owns the transaction (like ``app.escalations.process_escalation``), so the state
change and its events are stored together or not at all.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AuditEvent, Incident, IncidentEvent
from app.domain import TIMELINE_EVENT_TYPES, IncidentState, validate_transition

AUDIT_EVENT_TYPE = "incident.state_changed"


class StateClaimConflict(Exception):
    """The incident was not in any of the expected states, so another request got there first (or it moved on)."""

    code = "STATE_CLAIM_CONFLICT"

    def __init__(self, incident_id: int, expected: Iterable[str], target: str, actual: str | None):
        self.incident_id = incident_id
        self.expected = sorted(str(state) for state in expected)
        self.target = str(target)
        self.actual = actual
        super().__init__(
            f"Incident {incident_id} could not be moved to {self.target}: it is {actual or 'unknown'}, "
            f"expected one of {', '.join(self.expected)}."
        )


def default_event_type(target: str) -> str:
    """The timeline event type for a transition, following the existing PATCH /incidents/{id}/state convention."""
    return "RESOLUTION" if target == IncidentState.RESOLVED else "POLICY_DECISION"


def _checked_event_type(event_type: str | None, target: str) -> str:
    chosen = event_type or default_event_type(target)
    if chosen not in TIMELINE_EVENT_TYPES:
        raise ValueError(f"Unknown timeline event type: {chosen}")
    return chosen


def _record(
    session: AsyncSession,
    incident: Incident,
    *,
    previous: str | None,
    target: str,
    actor: str,
    reason: str,
    event_type: str,
    metadata: dict[str, Any] | None,
) -> IncidentEvent:
    payload: dict[str, Any] = {**(metadata or {}), "from_state": previous, "to_state": target, "target_state": target, "actor": actor}
    event = IncidentEvent(incident_id=incident.id, event_type=event_type, description=reason, metadata_json=json.dumps(payload))
    session.add(event)
    session.add(
        AuditEvent(
            event_type=AUDIT_EVENT_TYPE,
            message=f"Incident {incident.id} moved {previous or 'unknown'} -> {target} by {actor}: {reason}",
            is_demo=incident.is_demo,
        )
    )
    return event


def transition_incident(
    session: AsyncSession,
    incident: Incident,
    target: str,
    *,
    actor: str,
    reason: str,
    event_type: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> IncidentEvent:
    """Move ``incident`` to ``target`` if the state machine allows it, and record the change.

    Raises ``InvalidIncidentTransition`` (a ``ValueError``) for an unknown or disallowed transition and ``ValueError`` for
    an unknown ``event_type``; nothing is changed or recorded in either case. Sets ``resolution_timestamp`` when the
    target is RESOLVED, as every existing resolution path does. Does not commit.
    """
    previous = str(incident.state)
    validate_transition(previous, target)
    chosen = _checked_event_type(event_type, target)
    incident.state = IncidentState(target).value
    if target == IncidentState.RESOLVED:
        incident.resolution_timestamp = datetime.now(timezone.utc)
    return _record(session, incident, previous=previous, target=str(target), actor=actor, reason=reason, event_type=chosen, metadata=metadata)


async def claim_state(
    session: AsyncSession,
    incident: Incident,
    from_states: Iterable[str],
    to_state: str,
    *,
    actor: str,
    reason: str,
    event_type: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> IncidentEvent:
    """Atomically move ``incident`` from any of ``from_states`` to ``to_state``; exactly one concurrent caller wins.

    Every state in ``from_states`` must have a direct transition to ``to_state`` in the existing state machine
    (``InvalidIncidentTransition`` otherwise, before the database is touched). The claim is a conditional
    ``UPDATE incidents SET state = :to WHERE id = :id AND state = :source`` evaluated against the *stored* state, never
    the possibly stale loaded object. If no expected state matches, ``StateClaimConflict`` is raised and nothing is
    recorded. On success the incident is refreshed and the events are added. Does not commit.

    The recorded ``from_state`` is the stored state that this claim actually replaced, never the loaded object's state:
    the claim tries each expected state with its own conditional ``UPDATE ... WHERE id = :id AND state = :source``, and
    the statement that matches identifies the replaced state. ``expected_states`` lists the states the caller allowed.
    Do not call this with unflushed manual changes to ``incident.state``.
    """
    sources = list(dict.fromkeys(str(state) for state in from_states))
    if not sources:
        raise ValueError("claim_state needs at least one expected state.")
    for source in sources:
        validate_transition(source, to_state)
    chosen = _checked_event_type(event_type, to_state)

    values: dict[str, Any] = {"state": IncidentState(to_state).value}
    if to_state == IncidentState.RESOLVED:
        values["resolution_timestamp"] = datetime.now(timezone.utc)
    # One conditional UPDATE per expected state, in the caller's transaction. A statement that matches a row proves the
    # row was in exactly that state when it was replaced, so the previous state needs no separate (racy) read. The new
    # state is never one of the expected states (the state machine has no self-transitions), so at most one matches.
    previous: str | None = None
    for source in sources:
        claimed = await session.execute(
            update(Incident)
            .execution_options(synchronize_session=False)
            .where(Incident.id == incident.id, Incident.state == source)
            .values(**values)
        )
        if claimed.rowcount == 1:
            previous = source
            break
    if previous is None:
        await session.refresh(incident, ["state"])
        raise StateClaimConflict(incident.id, sources, str(to_state), str(incident.state))
    await session.refresh(incident, ["state", "resolution_timestamp"])
    merged = {**(metadata or {}), "expected_states": sorted(sources)}
    return _record(
        session,
        incident,
        previous=previous,
        target=str(to_state),
        actor=actor,
        reason=reason,
        event_type=chosen,
        metadata=merged,
    )
