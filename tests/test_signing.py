from datetime import datetime, timedelta, timezone

from trusthandoff import AgentIdentity, Permissions, SignedTaskPacket, sign_packet


def test_sign_packet_updates_signature():
    identity = AgentIdentity.generate()

    packet = SignedTaskPacket(
        packet_id="pk_sign_001",
        task_id="task_sign_001",
        from_agent=identity.agent_id,
        to_agent="agent:research:beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-sign-001",
        intent="Sign this packet",
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

    assert signed_packet.signature != ""
    assert signed_packet.signature != packet.signature
    assert signed_packet.from_agent == identity.agent_id
