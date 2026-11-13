"""T0 foundations: validated and recorded state transitions, atomic state claims, and soft/hard policy rejections.

These helpers are not wired into the API yet, so the tests exercise them directly against the isolated test database.
"""
import asyncio
import json
from datetime import datetime, timezone
from itertools import product
from uuid import uuid4

import pytest
from sqlalchemy import select

from app.database import AuditEvent, Incident, IncidentEvent, Service, session_factory
from app.domain import ALLOWED_TRANSITIONS, InvalidIncidentTransition, IncidentState
from app.lifecycle import AUDIT_EVENT_TYPE, StateClaimConflict, claim_state, transition_incident
from app.recovery import SOFT_REJECTION_CODES, PolicyRejected, consume_approval, get_action, validate_policy

S = IncidentState


# --- helpers ---------------------------------------------------------------------------------------------------------


async def make_incident(state: str = "DETECTED") -> int:
    async with session_factory() as session:
        service = Service(name=f"Lifecycle {uuid4()}", environment="demo", simulation_status=True)
        session.add(service)
        await session.flush()
        incident = Incident(
            service_id=service.id,
            severity="high",
            state=state,
            summary="Lifecycle test incident",
            deduplication_key=f"lifecycle-{uuid4()}",
            detection_timestamp=datetime.now(timezone.utc),
            is_demo=True,
        )
        session.add(incident)
        await session.commit()
        return incident.id


async def stored_state(incident_id: int) -> str:
    async with session_factory() as session:
        return (await session.get(Incident, incident_id)).state


async def recorded(incident_id: int) -> tuple[list[IncidentEvent], list[AuditEvent]]:
    async with session_factory() as session:
        events = list((await session.scalars(select(IncidentEvent).where(IncidentEvent.incident_id == incident_id))).all())
        audits = list(
            (await session.scalars(select(AuditEvent).where(AuditEvent.message.like(f"Incident {incident_id} moved %")))).all()
        )
    return events, audits


# --- the state machine is unchanged ----------------------------------------------------------------------------------


def test_the_state_machine_rules_are_unchanged():
    assert {state.value: sorted(target.value for target in targets) for state, targets in ALLOWED_TRANSITIONS.items()} == {
        "DETECTED": ["ESCALATED", "INVESTIGATING", "VERIFYING"],
        "INVESTIGATING": ["AWAITING_APPROVAL", "ESCALATED", "RECOVERING", "VERIFYING"],
        "AWAITING_APPROVAL": ["ESCALATED", "RECOVERING", "VERIFYING"],
        "RECOVERING": ["ESCALATED", "FAILED", "VERIFYING"],
        "VERIFYING": ["ESCALATED", "FAILED", "RESOLVED"],
        "RESOLVED": [],
        "ESCALATED": ["INVESTIGATING"],
        "FAILED": ["ESCALATED", "INVESTIGATING"],
    }


# --- transition_incident ---------------------------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(("current", "target"), list(product(S, S)), ids=lambda value: value.value)
async def test_every_state_pair_follows_the_state_machine_and_records_only_valid_changes(current, target):
    incident_id = await make_incident(current.value)
    allowed = target in ALLOWED_TRANSITIONS[current]

    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        if allowed:
            transition_incident(session, incident, target, actor="tester", reason="matrix")
            await session.commit()
        else:
            with pytest.raises(InvalidIncidentTransition):
                transition_incident(session, incident, target, actor="tester", reason="matrix")
            await session.rollback()

    events, audits = await recorded(incident_id)
    if allowed:
        assert await stored_state(incident_id) == target.value
        assert len(events) == 1 and len(audits) == 1
    else:
        assert await stored_state(incident_id) == current.value  # unchanged
        assert events == [] and audits == []  # nothing recorded for a refused transition


@pytest.mark.asyncio
async def test_unknown_states_are_rejected_without_changes():
    incident_id = await make_incident("DETECTED")
    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        with pytest.raises(InvalidIncidentTransition):
            transition_incident(session, incident, "NOT_A_STATE", actor="tester", reason="bad")
        await session.rollback()
    assert await stored_state(incident_id) == "DETECTED"
    assert await recorded(incident_id) == ([], [])


@pytest.mark.asyncio
async def test_a_transition_records_one_incident_event_and_one_audit_event_with_the_actor():
    incident_id = await make_incident("DETECTED")
    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        transition_incident(
            session, incident, S.INVESTIGATING, actor="alice", reason="Started triage", metadata={"ticket": "T-1"}
        )
        await session.commit()

    events, audits = await recorded(incident_id)
    assert len(events) == 1 and len(audits) == 1
    event, audit = events[0], audits[0]
    assert event.event_type == "POLICY_DECISION"  # same default as PATCH /incidents/{id}/state
    assert event.description == "Started triage"
    assert json.loads(event.metadata_json) == {
        "ticket": "T-1", "from_state": "DETECTED", "to_state": "INVESTIGATING", "target_state": "INVESTIGATING", "actor": "alice",
    }
    assert audit.event_type == AUDIT_EVENT_TYPE == "incident.state_changed"
    assert audit.message == f"Incident {incident_id} moved DETECTED -> INVESTIGATING by alice: Started triage"
    assert audit.is_demo is True


@pytest.mark.asyncio
async def test_resolving_records_a_resolution_event_and_sets_the_resolution_timestamp():
    incident_id = await make_incident("VERIFYING")
    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        transition_incident(session, incident, S.RESOLVED, actor="system", reason="Verified")
        await session.commit()
    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        assert incident.state == "RESOLVED" and incident.resolution_timestamp is not None
    events, _ = await recorded(incident_id)
    assert [event.event_type for event in events] == ["RESOLUTION"]


@pytest.mark.asyncio
async def test_an_explicit_timeline_event_type_is_used_and_an_unknown_one_changes_nothing():
    incident_id = await make_incident("DETECTED")
    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        with pytest.raises(ValueError):
            transition_incident(session, incident, S.ESCALATED, actor="t", reason="x", event_type="NOT_AN_EVENT")
        assert incident.state == "DETECTED"  # not even in memory
        transition_incident(session, incident, S.ESCALATED, actor="t", reason="x", event_type="ESCALATION_CREATED")
        await session.commit()
    events, audits = await recorded(incident_id)
    assert [event.event_type for event in events] == ["ESCALATION_CREATED"] and len(audits) == 1


# --- claim_state -----------------------------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_claim_moves_the_stored_state_and_records_the_change():
    incident_id = await make_incident("AWAITING_APPROVAL")
    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        await claim_state(
            session, incident, [S.INVESTIGATING, S.AWAITING_APPROVAL], S.RECOVERING,
            actor="worker", reason="Recovery claimed", event_type="RECOVERY_STARTED",
        )
        assert incident.state == "RECOVERING"  # the loaded object is refreshed
        await session.commit()

    assert await stored_state(incident_id) == "RECOVERING"
    events, audits = await recorded(incident_id)
    assert [event.event_type for event in events] == ["RECOVERY_STARTED"] and len(audits) == 1
    metadata = json.loads(events[0].metadata_json)
    assert metadata["expected_states"] == ["AWAITING_APPROVAL", "INVESTIGATING"]
    assert metadata["from_state"] == "AWAITING_APPROVAL" and metadata["to_state"] == "RECOVERING" and metadata["actor"] == "worker"


@pytest.mark.asyncio
async def test_a_multi_state_claim_records_the_stored_previous_state_not_a_stale_loaded_one():
    incident_id = await make_incident("INVESTIGATING")
    async with session_factory() as claimer:
        stale = await claimer.get(Incident, incident_id)
        assert stale.state == "INVESTIGATING"
        async with session_factory() as other:  # the stored state moves on while `stale` still says INVESTIGATING
            moved = await other.get(Incident, incident_id)
            transition_incident(other, moved, S.AWAITING_APPROVAL, actor="other", reason="Approval requested")
            await other.commit()
        assert stale.state == "INVESTIGATING"  # the loaded object really is stale

        await claim_state(
            claimer, stale, [S.INVESTIGATING, S.AWAITING_APPROVAL], S.RECOVERING,
            actor="claimer", reason="Recovery claimed", event_type="RECOVERY_STARTED",
        )
        assert stale.state == "RECOVERING"
        await claimer.commit()

    assert await stored_state(incident_id) == "RECOVERING"
    events, audits = await recorded(incident_id)
    claim_event = next(event for event in events if json.loads(event.metadata_json)["actor"] == "claimer")
    claim_audit = next(audit for audit in audits if " by claimer:" in audit.message)
    metadata = json.loads(claim_event.metadata_json)

    assert claim_event.event_type == "RECOVERY_STARTED"
    assert metadata["from_state"] == "AWAITING_APPROVAL" and metadata["to_state"] == "RECOVERING"
    assert metadata["expected_states"] == ["AWAITING_APPROVAL", "INVESTIGATING"]  # what the caller allowed is still recorded
    assert claim_audit.message == f"Incident {incident_id} moved AWAITING_APPROVAL -> RECOVERING by claimer: Recovery claimed"
    assert "INVESTIGATING" not in claim_audit.message  # the stale state never appears in the claim's audit entry


@pytest.mark.asyncio
async def test_a_claim_from_the_first_of_several_expected_states_records_that_state():
    incident_id = await make_incident("INVESTIGATING")
    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        await claim_state(session, incident, [S.AWAITING_APPROVAL, S.INVESTIGATING, S.AWAITING_APPROVAL], S.RECOVERING, actor="w", reason="claim")
        await session.commit()
    events, audits = await recorded(incident_id)
    metadata = json.loads(events[0].metadata_json)
    assert metadata["from_state"] == "INVESTIGATING"
    assert metadata["expected_states"] == ["AWAITING_APPROVAL", "INVESTIGATING"]  # duplicates in the input are collapsed
    assert audits[0].message == f"Incident {incident_id} moved INVESTIGATING -> RECOVERING by w: claim"


@pytest.mark.asyncio
async def test_a_claim_from_the_wrong_state_conflicts_and_records_nothing():
    incident_id = await make_incident("VERIFYING")
    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        with pytest.raises(StateClaimConflict) as raised:
            await claim_state(session, incident, [S.INVESTIGATING], S.RECOVERING, actor="worker", reason="claim")
        await session.rollback()
    assert raised.value.actual == "VERIFYING" and raised.value.expected == ["INVESTIGATING"] and raised.value.code == "STATE_CLAIM_CONFLICT"
    assert await stored_state(incident_id) == "VERIFYING"
    assert await recorded(incident_id) == ([], [])


@pytest.mark.asyncio
async def test_a_claim_uses_the_stored_state_not_a_stale_loaded_object():
    incident_id = await make_incident("INVESTIGATING")
    async with session_factory() as stale_session:
        stale = await stale_session.get(Incident, incident_id)
        assert stale.state == "INVESTIGATING"
        async with session_factory() as other:  # someone else gets there first
            other_incident = await other.get(Incident, incident_id)
            await claim_state(other, other_incident, [S.INVESTIGATING], S.RECOVERING, actor="first", reason="first claim")
            await other.commit()
        with pytest.raises(StateClaimConflict) as raised:
            await claim_state(stale_session, stale, [S.INVESTIGATING], S.RECOVERING, actor="second", reason="second claim")
        await stale_session.rollback()
    assert raised.value.actual == "RECOVERING"
    events, audits = await recorded(incident_id)
    assert len(events) == 1 and len(audits) == 1  # only the first claim was recorded


@pytest.mark.asyncio
async def test_claim_arguments_are_checked_against_the_state_machine_before_touching_the_database():
    incident_id = await make_incident("DETECTED")
    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        with pytest.raises(InvalidIncidentTransition):  # DETECTED cannot go straight to RECOVERING
            await claim_state(session, incident, [S.DETECTED], S.RECOVERING, actor="w", reason="r")
        with pytest.raises(InvalidIncidentTransition):  # one illegal source among legal ones
            await claim_state(session, incident, [S.INVESTIGATING, S.DETECTED], S.RECOVERING, actor="w", reason="r")
        with pytest.raises(ValueError):
            await claim_state(session, incident, [], S.RECOVERING, actor="w", reason="r")
        with pytest.raises(ValueError):
            await claim_state(session, incident, [S.INVESTIGATING], S.RECOVERING, actor="w", reason="r", event_type="NOPE")
        await session.rollback()
    assert await stored_state(incident_id) == "DETECTED"
    assert await recorded(incident_id) == ([], [])


@pytest.mark.asyncio
async def test_only_one_of_several_concurrent_claims_wins():
    incident_id = await make_incident("INVESTIGATING")
    workers = 4
    barrier = asyncio.Barrier(workers)  # every worker has loaded the incident before any of them claims it

    async def attempt(number: int):
        async with session_factory() as session:
            incident = await session.get(Incident, incident_id)
            assert incident.state == "INVESTIGATING"
            await barrier.wait()
            try:
                await claim_state(session, incident, [S.INVESTIGATING], S.RECOVERING, actor=f"worker-{number}", reason="claim")
                await session.commit()
                return ("won", number)
            except StateClaimConflict as conflict:
                await session.rollback()
                return ("lost", conflict.actual)

    results = await asyncio.gather(*(attempt(number) for number in range(workers)))

    winners = [result for result in results if result[0] == "won"]
    losers = [result for result in results if result[0] == "lost"]
    assert len(winners) == 1 and len(losers) == workers - 1
    assert all(actual == "RECOVERING" for _, actual in losers)
    assert await stored_state(incident_id) == "RECOVERING"
    events, audits = await recorded(incident_id)
    assert len(events) == 1 and len(audits) == 1
    assert json.loads(events[0].metadata_json)["actor"] == f"worker-{winners[0][1]}"


@pytest.mark.asyncio
@pytest.mark.parametrize("helper", ["transition_incident", "claim_state"])
async def test_rolling_back_after_a_successful_helper_restores_the_state_and_discards_both_events(helper):
    incident_id = await make_incident("VERIFYING")
    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        if helper == "transition_incident":
            transition_incident(session, incident, S.RESOLVED, actor="tester", reason="Verified")
        else:
            await claim_state(session, incident, [S.VERIFYING], S.RESOLVED, actor="tester", reason="Verified")
        await session.flush()

        # Inside the transaction the change and both records exist (so a missing rollback would be noticed).
        assert incident.state == "RESOLVED" and incident.resolution_timestamp is not None
        in_flight_events = (await session.scalars(select(IncidentEvent).where(IncidentEvent.incident_id == incident_id))).all()
        in_flight_audits = (await session.scalars(select(AuditEvent).where(AuditEvent.message.like(f"Incident {incident_id} moved %")))).all()
        assert len(in_flight_events) == 1 and len(in_flight_audits) == 1

        await session.rollback()

    async with session_factory() as session:
        restored = await session.get(Incident, incident_id)
        assert restored.state == "VERIFYING" and restored.resolution_timestamp is None
    assert await recorded(incident_id) == ([], [])


# --- PolicyRejected.escalates ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("code", sorted(SOFT_REJECTION_CODES))
def test_routine_rejections_do_not_escalate(code):
    assert PolicyRejected("refused", code).escalates is False


@pytest.mark.parametrize("code", ["UNSAFE_TARGET", "MISSING_EVIDENCE", "INVALID_PARAMETERS", "UNKNOWN_ACTION"])
def test_safety_rejections_escalate(code):
    assert PolicyRejected("refused", code).escalates is True


def test_unknown_and_default_codes_escalate_so_a_new_code_is_never_silently_routine():
    assert PolicyRejected("refused").escalates is True and PolicyRejected("refused").code == "POLICY_REJECTED"
    assert PolicyRejected("refused", "SOME_FUTURE_CODE").escalates is True


def test_the_escalation_flag_can_be_set_explicitly_and_the_existing_signature_still_works():
    assert PolicyRejected("refused", "APPROVAL_REQUIRED", escalates=True).escalates is True
    assert PolicyRejected("refused", "UNSAFE_TARGET", escalates=False).escalates is False
    error = PolicyRejected("refused", "APPROVAL_REQUIRED")
    assert isinstance(error, ValueError) and str(error) == "refused" and error.code == "APPROVAL_REQUIRED"


def test_the_rejections_recovery_actually_raises_have_the_expected_kind():
    service = Service(name="Policy", environment="demo", simulation_status=True)
    incident = Incident(state="DETECTED", diagnostic_evidence='{"source": "test"}')

    with pytest.raises(PolicyRejected) as unknown:
        get_action("run_shell_command")
    with pytest.raises(PolicyRejected) as resolved:
        validate_policy(Incident(state="RESOLVED", diagnostic_evidence='{"a": 1}'), service, "restart_demo_application", {})
    with pytest.raises(PolicyRejected) as unsafe:
        validate_policy(incident, Service(name="Prod", environment="production", simulation_status=False), "restart_demo_application", {})
    with pytest.raises(PolicyRejected) as no_evidence:
        validate_policy(Incident(state="DETECTED", diagnostic_evidence="{}"), service, "restart_demo_application", {})
    with pytest.raises(PolicyRejected) as bad_parameters:
        validate_policy(incident, service, "restart_demo_application", {"unexpected": True})
    with pytest.raises(PolicyRejected) as bad_instances:
        validate_policy(incident, service, "scale_demo_application", {"instances": 2})

    assert [(e.value.code, e.value.escalates) for e in (unknown, resolved, unsafe, no_evidence, bad_parameters, bad_instances)] == [
        ("UNKNOWN_ACTION", True),
        ("INVALID_INCIDENT_STATE", False),
        ("UNSAFE_TARGET", True),
        ("MISSING_EVIDENCE", True),
        ("INVALID_PARAMETERS", True),
        ("INVALID_PARAMETERS", True),
    ]


@pytest.mark.asyncio
async def test_a_missing_approval_is_a_routine_rejection():
    incident_id = await make_incident("INVESTIGATING")
    async with session_factory() as session:
        incident = await session.get(Incident, incident_id)
        with pytest.raises(PolicyRejected) as raised:
            await consume_approval(session, incident, get_action("restore_known_good_configuration"), {}, "tester")
        await session.rollback()
    assert raised.value.code == "APPROVAL_REQUIRED" and raised.value.escalates is False
