from datetime import datetime, timedelta, timezone

from trusthandoff import Permissions, SignedTaskPacket, validate_packet


def test_validate_packet_returns_true_for_valid_packet():
    packet = SignedTaskPacket(
        packet_id="pk_valid_001",
        task_id="task_valid_001",
        from_agent="agent:planner:alpha",
        to_agent="agent:research:beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-valid-001",
        intent="Validate this packet",
        context={"company": "Example Corp"},
        permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key="demo-public-key",
    )
    result = validate_packet(packet)
    assert result.is_valid is True


def test_validate_packet_returns_false_for_expired_packet():
    packet = SignedTaskPacket(
        packet_id="pk_expired_001",
        task_id="task_expired_001",
        from_agent="agent:planner:alpha",
        to_agent="agent:research:beta",
        issued_at=datetime.now(timezone.utc) - timedelta(minutes=20),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        nonce="nonce-expired-001",
        intent="Expired packet",
        context={"company": "Example Corp"},
        permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key="demo-public-key",
    )
    result = validate_packet(packet)
    assert result.is_valid is False
