from datetime import datetime, timezone, timedelta
from .packet import SignedTaskPacket

CLOCK_SKEW_TOLERANCE = timedelta(seconds=30)

def validate_packet(packet: SignedTaskPacket) -> bool:
    now = datetime.now(timezone.utc)

    if packet.issued_at - CLOCK_SKEW_TOLERANCE > packet.expires_at:
        return False

    if packet.expires_at + CLOCK_SKEW_TOLERANCE < now:
        return False

    return True
