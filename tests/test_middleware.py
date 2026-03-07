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


def test_middleware_handles_valid_envelope():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    packet = SignedTaskPacket(
        packet_id="pk_mw_001",
        task_id="task_mw_001",
        from_agent=planner.agent_id,
        to_agent=research.agent_id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-mw-001",
        intent="Middleware test",
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
    decision = middleware.handle(envelope)

    assert decision.packet_id == signed_packet.packet_id
    assert decision.decision == "ACCEPT"
    assert decision.reason == "Packet verified and valid"
