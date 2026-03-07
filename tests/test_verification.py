from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    Permissions,
    SignedTaskPacket,
    sign_packet,
    verify_packet,
)


def test_verify_packet_returns_true_for_valid_signature():
    identity = AgentIdentity.generate()

    packet = SignedTaskPacket(
        packet_id="pk_verify_001",
        task_id="task_verify_001",
        from_agent=identity.agent_id,
        to_agent="agent:research:beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-verify-001",
        intent="Verify this packet",
        context={"company": "Example Corp"},
        permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        signature_algo="Ed25519",
        signature="",
        public_key=identity.public_key_pem,
    )

    signed_packet = sign_packet(packet, identity)

    assert verify_packet(signed_packet) is True
