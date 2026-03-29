from datetime import datetime, timezone, timedelta

from trusthandoff.packet import SignedTaskPacket, Permissions
from trusthandoff.validation import validate_packet
from trusthandoff.sentinel import Sentinel


def main():
    print("=== SENTINEL DEMO ===")

    issued = datetime.now(timezone.utc)

    # Force a rejection
    packet = SignedTaskPacket(
        packet_id="p1",
        task_id="t1",
        from_agent="a",
        to_agent="b",
        issued_at=issued,
        expires_at=issued - timedelta(seconds=1),  # expired
        nonce="n",
        intent="bad",
        permissions=Permissions(),
        signature_algo="algo",
        signature="sig",
        public_key="pk",
    )

    validate_packet(packet)

    sentinel = Sentinel()
    sentinel.ingest()
    sentinel.report()


if __name__ == "__main__":
    main()
