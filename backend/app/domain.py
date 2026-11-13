from enum import StrEnum


class IncidentState(StrEnum):
    DETECTED = "DETECTED"
    INVESTIGATING = "INVESTIGATING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    RECOVERING = "RECOVERING"
    VERIFYING = "VERIFYING"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"
    FAILED = "FAILED"


ALLOWED_TRANSITIONS: dict[IncidentState, set[IncidentState]] = {
    IncidentState.DETECTED: {IncidentState.INVESTIGATING, IncidentState.VERIFYING, IncidentState.ESCALATED},
    IncidentState.INVESTIGATING: {
        IncidentState.AWAITING_APPROVAL,
        IncidentState.RECOVERING,
        IncidentState.VERIFYING,
        IncidentState.ESCALATED,
    },
    IncidentState.AWAITING_APPROVAL: {IncidentState.RECOVERING, IncidentState.VERIFYING, IncidentState.ESCALATED},
    IncidentState.RECOVERING: {IncidentState.VERIFYING, IncidentState.FAILED, IncidentState.ESCALATED},
    IncidentState.VERIFYING: {IncidentState.RESOLVED, IncidentState.FAILED, IncidentState.ESCALATED},
    IncidentState.RESOLVED: set(),
    IncidentState.ESCALATED: {IncidentState.INVESTIGATING},
    IncidentState.FAILED: {IncidentState.INVESTIGATING, IncidentState.ESCALATED},
}


class InvalidIncidentTransition(ValueError):
    pass


def validate_transition(current: str, target: str) -> None:
    try:
        current_state = IncidentState(current)
        target_state = IncidentState(target)
    except ValueError as exc:
        raise InvalidIncidentTransition(f"Unknown incident state transition: {current} -> {target}") from exc
    if target_state not in ALLOWED_TRANSITIONS[current_state]:
        raise InvalidIncidentTransition(f"Transition not allowed: {current_state} -> {target_state}")


TIMELINE_EVENT_TYPES = {
    "DETECTION",
    "INVESTIGATION_STARTED",
    "INVESTIGATION_COMPLETED",
    "POLICY_DECISION",
    "RECOVERY_STARTED",
    "RECOVERY_COMPLETED",
    "VERIFICATION_COMPLETED",
    "ESCALATION_CREATED",
    "ADMIN_ACKNOWLEDGED",
    "RESOLUTION",
    "SERVICE_RECOVERED",
}

DEMO_SCENARIOS = {
    "healthy",
    "service_unavailable",
    "configuration_failure",
    "dependency_unavailable",
}
