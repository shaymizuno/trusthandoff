from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    AgentRegistry,
    DelegationChain,
    DelegationEnvelope,
    Permissions,
    SignedTaskPacket,
    sign_packet,
    verify_envelope,
)


def make_packet(agent_id: str, public_key: str, signature: str = "fake-signature") -> SignedTaskPacket:
    return SignedTaskPacket(
        packet_id="pkt-1",
        task_id="task-1",
        from_agent=agent_id,
        to_agent="agent:executor:alpha",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-identity-1",
        intent="identity binding test",
        context={},
        permissions=Permissions(
            allowed_actions=["read"],
            max_tool_calls=1,
        ),
        signature_algo="Ed25519",
        signature=signature,
        public_key=public_key,
    )


def test_reject_unknown_agent():
    registry = AgentRegistry()

    packet = make_packet("agent:planner:alpha", "key-1")
    envelope = DelegationEnvelope(
        packet=packet,
        chain=DelegationChain(
            packet_ids=[packet.packet_id],
            agents=[packet.from_agent],
        ),
    )

    decision = verify_envelope(envelope, registry=registry)

    assert decision.decision == "REJECT"
    assert decision.reason == "Unknown agent identity"


def test_reject_wrong_key():
    registry = AgentRegistry()
    registry.register("agent:planner:alpha", "key-expected")

    packet = make_packet("agent:planner:alpha", "key-attacker")
    envelope = DelegationEnvelope(
        packet=packet,
        chain=DelegationChain(
            packet_ids=[packet.packet_id],
            agents=[packet.from_agent],
        ),
    )

    decision = verify_envelope(envelope, registry=registry)

    assert decision.decision == "REJECT"
    assert decision.reason == "Agent identity binding failed"


def test_accept_correct_identity():
    planner = AgentIdentity.generate()
    registry = AgentRegistry()
    registry.register(planner.agent_id, planner.public_key_pem)

    packet = make_packet(planner.agent_id, planner.public_key_pem, signature="")
    signed_packet = sign_packet(packet, planner)

    envelope = DelegationEnvelope(
        packet=signed_packet,
        chain=DelegationChain(
            packet_ids=[signed_packet.packet_id],
            agents=[signed_packet.from_agent],
        ),
    )

    decision = verify_envelope(envelope, registry=registry)

    assert decision.decision == "ACCEPT"
    assert decision.reason == "Packet verified and valid"
