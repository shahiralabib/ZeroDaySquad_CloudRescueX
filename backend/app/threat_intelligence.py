from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_network


@dataclass(frozen=True)
class IndicatorRecord:
    indicator: str
    indicator_type: str
    reputation: str
    confidence: float
    techniques: tuple[str, ...]
    description: str
    source: str = "local_demo_dataset"


LOCAL_INDICATORS = (
    IndicatorRecord(
        "198.51.100.23",
        "ipv4",
        "suspicious_sample",
        0.91,
        ("T1110",),
        "Reserved documentation address used to model repeated authentication failures.",
    ),
    IndicatorRecord(
        "203.0.113.44",
        "ipv4",
        "suspicious_sample",
        0.84,
        ("T1071.001",),
        "Reserved documentation address used to model unusual web traffic.",
    ),
    IndicatorRecord(
        "login.example.invalid",
        "domain",
        "suspicious_sample",
        0.79,
        ("T1583.001",),
        "Non-resolving sample domain used for the offline demonstration.",
    ),
)


def lookup_indicator(value: str) -> dict[str, object]:
    normalized = value.strip().lower()
    exact = next((item for item in LOCAL_INDICATORS if item.indicator == normalized), None)
    if exact:
        return {
            "indicator": exact.indicator,
            "indicator_type": exact.indicator_type,
            "matched": True,
            "reputation": exact.reputation,
            "confidence": exact.confidence,
            "mitre_attack_techniques": list(exact.techniques),
            "description": exact.description,
            "source": exact.source,
            "simulated": True,
        }
    try:
        address = ip_address(normalized)
    except ValueError:
        address = None
    if address and any(address in network for network in (ip_network("198.51.100.0/24"), ip_network("203.0.113.0/24"))):
        return {
            "indicator": normalized,
            "indicator_type": "ipv4",
            "matched": True,
            "reputation": "reserved_sample_range",
            "confidence": 0.55,
            "mitre_attack_techniques": [],
            "description": "Reserved documentation range; not a live threat-intelligence result.",
            "source": "local_demo_dataset",
            "simulated": True,
        }
    return {
        "indicator": normalized,
        "indicator_type": "unknown",
        "matched": False,
        "reputation": "unknown",
        "confidence": 0,
        "mitre_attack_techniques": [],
        "description": "No match in the local offline dataset.",
        "source": "local_demo_dataset",
        "simulated": True,
    }


OBSERVABLE_FIELDS = ("source_ip", "domain")


def enrich_telemetry_metadata(metadata: dict[str, object]) -> dict[str, object] | None:
    """Look up the first indicator found in telemetry metadata in the offline dataset.

    Returns the lookup result plus the metadata field it came from, or None when the event carries no
    indicator. The lookup is local and makes no network request.
    """
    for field in OBSERVABLE_FIELDS:
        value = metadata.get(field)
        if isinstance(value, str) and value.strip():
            return {**lookup_indicator(value), "observable": field}
    return None


def threat_intelligence_factor(finding: dict[str, object]) -> int:
    """Priority factor (0-100): the dataset confidence for a match, a low baseline for an unknown indicator."""
    if finding.get("matched"):
        confidence = finding.get("confidence")
        return round(float(confidence) * 100) if isinstance(confidence, (int, float)) else 50
    return 25
