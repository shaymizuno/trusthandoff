from datetime import datetime, timezone, timedelta

from trusthandoff.packet import SignedTaskPacket, Permissions
from trusthandoff.validation import validate_packet

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


def test_validate_packet_strict_default_ttl_policy(monkeypatch):
    monkeypatch.setenv("TRUSTHANDOFF_ENFORCE_DEFAULT_TTL_POLICY", "1")

    # Re-import module-level flag by reloading validation
    import importlib
    import trusthandoff.validation as validation_module
    importlib.reload(validation_module)

    issued = datetime.now(timezone.utc)

    # Legacy packet with 10 min TTL should fail under strict default read policy (900s)
    packet = SignedTaskPacket(
        packet_id="strict-1",
        task_id="task-strict",
        from_agent="a",
        to_agent="b",
        issued_at=issued,
        expires_at=issued + timedelta(minutes=10),  # 600s, mismatch vs read=900s
        nonce="n",
        intent="read_something",
        permissions=Permissions(),
        signature_algo="algo",
        signature="sig",
        public_key="pk",
    )

    result = validation_module.validate_packet(packet)
    assert result.is_valid is False
    assert result.reason == "ttl_policy_mismatch"
