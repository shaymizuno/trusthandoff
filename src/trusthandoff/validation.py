import os
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

from .packet import SignedTaskPacket
from .decorators import DEFAULT_POLICY

MAX_ISSUANCE_SKEW_SECONDS = 300
MAX_EXPIRY_GRACE_SECONDS = 60

_raw_issuance_skew = int(os.getenv("TRUSTHANDOFF_ISSUANCE_SKEW", "30"))
_raw_expiry_grace = int(os.getenv("TRUSTHANDOFF_EXPIRY_GRACE", "0"))

# New: optional strict global TTL enforcement
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
      fallback to DEFAULT_POLICY['read'].
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

def validate_packet(
    packet: SignedTaskPacket,
    issuance_skew: timedelta = ISSUANCE_SKEW_TOLERANCE,
    expiry_grace: timedelta = EXPIRY_GRACE,
) -> PacketValidationResult:
    now = datetime.now(timezone.utc)

    if packet.issued_at > packet.expires_at:
        return PacketValidationResult(False, "malformed_time_window")

    if packet.issued_at - issuance_skew > now:
        return PacketValidationResult(False, "issued_in_future")

    if _requires_human_review(packet):
        human_approval = packet.context.get("human_approval")

        if not human_approval:
            return PacketValidationResult(False, "human_review_required")

    expected_ttl_seconds = _resolve_expected_ttl_seconds(packet)

    if expected_ttl_seconds == -1:
        return PacketValidationResult(False, "unsupported_risk_level")

    if expected_ttl_seconds is not None:
        expected_expires_at = packet.issued_at + timedelta(seconds=expected_ttl_seconds)
        if packet.expires_at != expected_expires_at:
            return PacketValidationResult(False, "ttl_policy_mismatch")

    if packet.expires_at + expiry_grace < now:
        return PacketValidationResult(False, "expired")

    return PacketValidationResult(True, None)
