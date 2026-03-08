from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    DelegationChain,
    DelegationEnvelope,
    Permissions,
    SignedTaskPacket,
    TrustHandoffMiddleware,
    envelope_from_json,
    envelope_to_json,
    sign_packet,
)


def main():
    print("=== TrustHandoff Wire Flow Demo ===")

    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    packet = SignedTaskPacket(
        packet_id="pk_wire_demo_001",
        task_id="task_wire_demo_001",
        from_agent=planner.agent_id,
        to_agent=research.agent_id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-wire-demo-001",
        intent="Research company background",
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

    payload = envelope_to_json(envelope)
    rebuilt_envelope = envelope_from_json(payload)

    middleware = TrustHandoffMiddleware(max_depth=5)
    decision = middleware.handle(rebuilt_envelope)

    print("Wire payload:")
    print(payload)
    print()
    print("Decision:", decision.decision)
    print("Reason:", decision.reason)


if __name__ == "__main__":
    main()
