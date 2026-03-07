from datetime import datetime, timedelta, timezone

from trusthandoff import SignedTaskPacket, Permissions


def test_signed_task_packet_creation():
    packet = SignedTaskPacket(
        packet_id="pk_001",
        task_id="task_001",
        from_agent="agent:planner:alpha",
        to_agent="agent:research:beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="abc123",
        intent="Research company background",
        context={"company": "Example Corp"},
        permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=5,
        ),
        signature_algo="Ed25519",
        signature="fake",
        public_key="fake",
    )

    assert packet.task_id == "task_001"
