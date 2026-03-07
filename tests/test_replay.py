from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    DelegationChain,
    DelegationEnvelope,
    Permissions,
    SignedTaskPacket,
    TrustHandoffMiddleware,
    sign_packet,
)


def test_middleware_rejects_replayed_packet():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    packet = SignedTaskPacket(
        packet_id="pk_replay_001",
        task_id="task_replay_001",
        from_agent=planner.agent_id,
        to_agent=research.agent_id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-replay-001",
        intent="Replay test",
        context={"company": "Example Corp"},
        permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        signature_algo="Ed25519",
        signature="",
        public_key=planner.public_key_pem,
    )

    signed_packet = sign_packet(packet, planner)

    envelope = DelegationEnvelope(
        packet=signed_packet,
        chain=DelegationChain(
            packet_ids=[signed_packet.packet_id],
            agents=[planner.agent_id],
        ),
    )

    middleware = TrustHandoffMiddleware()

    first_decision = middleware.handle(envelope)
    second_decision = middleware.handle(envelope)

    assert first_decision.decision == "ACCEPT"
    assert second_decision.decision == "REJECT"
    assert second_decision.reason == "Replay detected"
