import os
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional

from .agent_registry import AgentRegistry
from .packet import SignedTaskPacket
from .decorators import DEFAULT_POLICY
from .errors import PublicKeyMismatchError
from .events import emit_event
from .overlap import is_overlap_valid
from .verification import _check_registry_binding

MAX_ISSUANCE_SKEW_SECONDS = 300
MAX_EXPIRY_GRACE_SECONDS = 60

_raw_issuance_skew = int(os.getenv("TRUSTHANDOFF_ISSUANCE_SKEW", "30"))
_raw_expiry_grace = int(os.getenv("TRUSTHANDOFF_EXPIRY_GRACE", "0"))

# Optional strict global TTL enforcement
TRUSTHANDOFF_ENFORCE_DEFAULT_TTL_POLICY = os.getenv(
    "TRUSTHANDOFF_ENFORCE_DEFAULT_TTL_POLICY",
    "0",
).lower() in {"1", "true", "yes"}

DEFAULT_ISSUANCE_SKEW_SECONDS = min(
    max(_raw_issuance_skew, 0),
    MAX_ISSUANCE_SKEW_SECONDS,
)
DEFAULT_EXPIRY_GRACE_SECONDS = min(
    max(_raw_expiry_grace, 0),
    MAX_EXPIRY_GRACE_SECONDS,
)

ISSUANCE_SKEW_TOLERANCE = timedelta(seconds=DEFAULT_ISSUANCE_SKEW_SECONDS)
EXPIRY_GRACE = timedelta(seconds=DEFAULT_EXPIRY_GRACE_SECONDS)


@dataclass(frozen=True)
class PacketValidationResult:
    is_valid: bool
    reason: str | None = None


def _resolve_expected_ttl_seconds(packet: SignedTaskPacket) -> int | None:
    """
    Resolve the TTL policy expected for this packet.

    Rules:
    - If packet explicitly carries risk_level / ttl_seconds, enforce them.
    - If strict global enforcement is enabled and packet carries no metadata,
      fallback to DEFAULT_POLICY["read"].
    - Otherwise return None (legacy behavior unchanged).
    """
    if packet.ttl_seconds is not None:
        return packet.ttl_seconds

    if packet.risk_level is not None:
        risk = packet.risk_level
        if risk not in DEFAULT_POLICY:
            return -1  # invalid risk_level marker
        return DEFAULT_POLICY[risk]

    if TRUSTHANDOFF_ENFORCE_DEFAULT_TTL_POLICY:
        return DEFAULT_POLICY["read"]

    return None


def _requires_human_review(packet: SignedTaskPacket) -> bool:
    return bool(packet.constraints and packet.constraints.requires_human_review)


def _emit_rejected(packet: SignedTaskPacket, reason: str) -> None:
    emit_event(
        "packet_rejected",
        {
            "packet_id": packet.packet_id,
            "task_id": packet.task_id,
            "from_agent": packet.from_agent,
            "to_agent": packet.to_agent,
            "reason": reason,
            "risk_level": getattr(packet, "risk_level", None),
            "ttl_seconds": getattr(packet, "ttl_seconds", None),
        },
    )


def _emit_accepted(packet: SignedTaskPacket) -> None:
    emit_event(
        "packet_accepted",
        {
            "packet_id": packet.packet_id,
            "task_id": packet.task_id,
            "from_agent": packet.from_agent,
            "to_agent": packet.to_agent,
            "risk_level": getattr(packet, "risk_level", None),
            "ttl_seconds": getattr(packet, "ttl_seconds", None),
        },
    )


def validate_packet(
    packet: SignedTaskPacket,
    issuance_skew: timedelta = ISSUANCE_SKEW_TOLERANCE,
    expiry_grace: timedelta = EXPIRY_GRACE,
    registry: Optional[AgentRegistry] = None,
) -> PacketValidationResult:
    now = datetime.now(timezone.utc)

    if registry is not None:
        try:
            _check_registry_binding(packet, registry)
        except PublicKeyMismatchError:
            _emit_rejected(packet, "public_key_mismatch")
            return PacketValidationResult(False, "public_key_mismatch")

    if packet.issued_at > packet.expires_at:
        _emit_rejected(packet, "malformed_time_window")
        return PacketValidationResult(False, "malformed_time_window")

    if packet.issued_at - issuance_skew > now:
        _emit_rejected(packet, "issued_in_future")
        return PacketValidationResult(False, "issued_in_future")

    if _requires_human_review(packet):
        human_approval = packet.context.get("human_approval")
        if not human_approval:
            _emit_rejected(packet, "human_review_required")
            return PacketValidationResult(False, "human_review_required")

    # AI provenance validation + observability
    if packet.ai_provenance is not None:
        if not isinstance(packet.ai_provenance, dict):
            _emit_rejected(packet, "invalid_ai_provenance")
            return PacketValidationResult(False, "invalid_ai_provenance")

        if "source" not in packet.ai_provenance:
            _emit_rejected(packet, "invalid_ai_provenance")
            return PacketValidationResult(False, "invalid_ai_provenance")

        emit_event(
            "ai_generated_payload",
            {
                "packet_id": packet.packet_id,
                "source": packet.ai_provenance.get("source"),
                "model": packet.ai_provenance.get("model"),
            },
        )

    expected_ttl_seconds = _resolve_expected_ttl_seconds(packet)

    if expected_ttl_seconds == -1:
        _emit_rejected(packet, "unsupported_risk_level")
        return PacketValidationResult(False, "unsupported_risk_level")

    if expected_ttl_seconds is not None:
        expected_expires_at = packet.issued_at + timedelta(seconds=expected_ttl_seconds)
        if packet.expires_at != expected_expires_at:
            _emit_rejected(packet, "ttl_policy_mismatch")
            return PacketValidationResult(False, "ttl_policy_mismatch")

    if packet.expires_at + expiry_grace < now:
        # overlap window check
        if is_overlap_valid(packet.packet_id):
            emit_event(
                "token_overlap_used",
                {
                    "packet_id": packet.packet_id,
                    "reason": "expired_but_within_overlap",
                },
            )
        else:
            _emit_rejected(packet, "expired")
            return PacketValidationResult(False, "expired")

    _emit_accepted(packet)
    return PacketValidationResult(True, None)
