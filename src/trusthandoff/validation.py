import os
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

from .packet import SignedTaskPacket


MAX_ISSUANCE_SKEW_SECONDS = 300
MAX_EXPIRY_GRACE_SECONDS = 60

_raw_issuance_skew = int(os.getenv("TRUSTHANDOFF_ISSUANCE_SKEW", "30"))
_raw_expiry_grace = int(os.getenv("TRUSTHANDOFF_EXPIRY_GRACE", "0"))

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

    if packet.expires_at + expiry_grace < now:
        return PacketValidationResult(False, "expired")

    return PacketValidationResult(True, None)
