from datetime import datetime, timedelta, timezone

from trusthandoff.packet import SignedTaskPacket, Permissions
from trusthandoff.validation import validate_packet


def test_packet_with_small_clock_skew_is_still_valid():
    now = datetime.now(timezone.utc)

    packet = SignedTaskPacket(
        packet_id="pkt-skew-1",
        task_id="task-skew-1",
        from_agent="agent:a",
        to_agent="agent:b",
        issued_at=now - timedelta(minutes=1),
        expires_at=now - timedelta(seconds=10),  # expired 10s ago
        nonce="nonce-skew-1",
        intent="search",
        permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=1,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key="demo-key",
    )

    assert validate_packet(packet) is True


def test_packet_beyond_clock_skew_tolerance_is_invalid():
    now = datetime.now(timezone.utc)

    packet = SignedTaskPacket(
        packet_id="pkt-skew-2",
        task_id="task-skew-2",
        from_agent="agent:a",
        to_agent="agent:b",
        issued_at=now - timedelta(minutes=1),
        expires_at=now - timedelta(seconds=45),  # expired too long ago
        nonce="nonce-skew-2",
        intent="search",
        permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=1,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key="demo-key",
    )

    assert validate_packet(packet) is False
