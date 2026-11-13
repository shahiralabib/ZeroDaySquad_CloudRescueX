"""Which recovery action genuinely remediates which kind of fault.

This is the single source of truth shared by the AI investigation (what to recommend) and by recovery
(what an action may change and what verification may accept). It is pure data and logic with no database
access, so a recommendation can never point at an action that verification would reject.

The simulated recovery catalog has no account, session, or network-traffic containment, so credential
attacks and network anomalies are never mapped to a recovery action: they are escalated to an administrator.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Recommended-action values that are not recovery actions.
ESCALATE_TO_ADMINISTRATOR = "escalate_to_administrator"  # manual containment is required
NO_ACTION = "none"  # nothing in the allowlist applies and no specific manual procedure is known

APPLICATION = "application"
CAPACITY = "capacity"
CONFIGURATION = "configuration"
DEPENDENCY = "dependency"
CREDENTIAL_ATTACK = "credential_attack"
NETWORK = "network"

WEB_SERVER = "web_server"
DEPENDENCY_RESOURCE_TYPES = frozenset({"database_server", "authentication_service"})

# Fault categories each recovery action remediates. Credential attacks and network anomalies appear in no entry.
ACTION_REMEDIATES: dict[str, frozenset[str]] = {
    "restart_demo_application": frozenset({APPLICATION, CAPACITY}),
    "scale_demo_application": frozenset({APPLICATION, CAPACITY}),
    "restore_known_good_configuration": frozenset({CONFIGURATION}),
    "restore_demo_dependency": frozenset({DEPENDENCY}),
    "reset_demo_environment": frozenset({APPLICATION, CAPACITY, CONFIGURATION, DEPENDENCY}),
}
# Resource types an action can act on for a telemetry incident (None = any resource type).
ACTION_RESOURCE_TYPES: dict[str, frozenset[str] | None] = {
    "restart_demo_application": frozenset({WEB_SERVER}),
    "scale_demo_application": frozenset({WEB_SERVER}),
    "restore_known_good_configuration": None,
    "restore_demo_dependency": DEPENDENCY_RESOURCE_TYPES,
    "reset_demo_environment": None,
}
# Category of a service outage, from the injected fault scenario (also the incident type of outage incidents).
OUTAGE_FAULT_CATEGORY: dict[str, str] = {
    "service_unavailable": APPLICATION,
    "configuration_failure": CONFIGURATION,
    "dependency_unavailable": DEPENDENCY,
}
# Category of a telemetry-detected incident, from its detection rule.
DETECTION_RULE_CATEGORY: dict[str, str] = {
    "repeated_failed_authentication": CREDENTIAL_ATTACK,
    "suspicious_login_pattern": CREDENTIAL_ATTACK,
    "unusual_network_connection": NETWORK,
    "unusual_network_traffic": NETWORK,
    "configuration_change": CONFIGURATION,
    "resource_exhaustion": CAPACITY,
    "service_availability": APPLICATION,
    "dependency_failure": DEPENDENCY,
}

# CPU or memory at or above this percentage counts as saturation, matching the simulation's "high" severity.
SATURATION_PERCENT = 90


def action_addresses(action_id: str, category: str | None, resource_type: str | None = None, *, check_resource: bool = True) -> bool:
    """True if the action remediates this fault category (and, for telemetry incidents, can act on this resource type)."""
    if category is None or category not in ACTION_REMEDIATES.get(action_id, frozenset()):
        return False
    allowed = ACTION_RESOURCE_TYPES.get(action_id)
    if check_resource and allowed is not None:
        return resource_type in allowed
    return True


@dataclass(frozen=True)
class Recommendation:
    action: str  # a recovery action id, ESCALATE_TO_ADMINISTRATOR, or NO_ACTION
    rationale: str


def _utilisation(metadata: Any) -> tuple[float | None, float | None]:
    def number(key: str) -> float | None:
        value = metadata.get(key) if isinstance(metadata, dict) else None
        return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None

    return number("cpu_percent"), number("memory_percent")


def recommend_telemetry_action(rule: str, resource_type: str | None, metadata: Any = None) -> Recommendation:
    """Choose the response for a telemetry-detected incident from its detection rule, affected resource and evidence."""
    category = DETECTION_RULE_CATEGORY.get(rule)
    if category is None:
        return Recommendation(NO_ACTION, f"No remediation is defined for detection rule '{rule}'.")
    if category == CREDENTIAL_ATTACK:
        return Recommendation(
            ESCALATE_TO_ADMINISTRATOR,
            "No available recovery action provides account or session containment, and restoring configuration does not "
            "stop a credential attack. Manual containment is required: block the source indicator at the perimeter, "
            "lock or reset the affected accounts, revoke active sessions, and review authentication logs.",
        )
    if category == NETWORK:
        return Recommendation(
            ESCALATE_TO_ADMINISTRATOR,
            "No available recovery action operates on network traffic controls, so this cannot be remediated automatically. "
            "An administrator should review the firewall and VPN logs and apply filtering or rate limits manually.",
        )
    if category == CONFIGURATION:
        return Recommendation(
            "restore_known_good_configuration",
            "The evidence shows a configuration change away from the known-good baseline on the affected asset.",
        )
    if category == DEPENDENCY:
        if resource_type in DEPENDENCY_RESOURCE_TYPES:
            return Recommendation(
                "restore_demo_dependency", f"The evidence shows the {resource_type.replace('_', ' ')} dependency is unavailable."
            )
        return Recommendation(
            ESCALATE_TO_ADMINISTRATOR,
            "The dependency recovery action only supports database and authentication services, and the affected asset is not one.",
        )
    if resource_type != WEB_SERVER:
        # restart and scale act on the application tier, so they cannot fix another tier.
        return Recommendation(
            ESCALATE_TO_ADMINISTRATOR,
            "Restart and scale only act on the web application tier, and the affected asset is a different tier. "
            "An administrator should investigate it manually.",
        )
    if category == CAPACITY:
        cpu, memory = _utilisation(metadata)
        peak = max((value for value in (cpu, memory) if value is not None), default=None)
        if peak is not None and peak >= SATURATION_PERCENT:
            return Recommendation(
                "scale_demo_application",
                f"CPU/memory peaked at {peak:g}%, at or above the {SATURATION_PERCENT}% saturation threshold, so the "
                "web application needs capacity (scaling to one instance).",
            )
        shown = f"{peak:g}%" if peak is not None else "an unknown level"
        return Recommendation(
            "restart_demo_application",
            f"Utilisation is elevated ({shown}) but below the {SATURATION_PERCENT}% saturation threshold, so there is no "
            "evidence capacity is exhausted; restarting the web application reclaims resources without scaling.",
        )
    return Recommendation("restart_demo_application", "The evidence shows the web application is not available.")
