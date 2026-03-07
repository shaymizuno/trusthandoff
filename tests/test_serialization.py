from datetime import datetime, timedelta, timezone

from trusthandoff import (
    Permissions,
    SignedTaskPacket,
    packet_from_dict,
    packet_to_dict,
)


def test_packet_serialization_roundtrip():
    packet = SignedTaskPacket(
        packet_id="pk_serial_001",
        task_id="task_serial_001",
        from_agent="agent:planner:alpha",
        to_agent="agent:research:beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-serial-001",
        intent="Serialize this packet",
        context={"company": "Example Corp"},
        permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key="demo-public-key",
    )

    data = packet_to_dict(packet)
    rebuilt_packet = packet_from_dict(data)

    assert rebuilt_packet.packet_id == packet.packet_id
    assert rebuilt_packet.task_id == packet.task_id
    assert rebuilt_packet.intent == packet.intent
    assert rebuilt_packet.permissions.allowed_actions == packet.permissions.allowed_actions
