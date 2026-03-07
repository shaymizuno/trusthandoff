from datetime import datetime, timedelta, timezone
from uuid import uuid4

from trusthandoff import (
    AgentIdentity,
    DelegationChain,
    DelegationEnvelope,
    Permissions,
    SignedTaskPacket,
    process_handoff,
    sign_packet,
)


def create_packet(
    source_identity: AgentIdentity,
    target_agent_id: str,
    state_intent: str,
    state_context: dict,
    allowed_actions: list[str] | None = None,
    max_tool_calls: int = 5,
    expires_in_minutes: int = 10,
) -> SignedTaskPacket:
    if allowed_actions is None:
        allowed_actions = ["read", "search", "summarize"]

    return SignedTaskPacket(
        packet_id=f"pk_{uuid4().hex}",
        task_id=f"task_{uuid4().hex}",
        from_agent=source_identity.agent_id,
        to_agent=target_agent_id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes),
        nonce=f"nonce_{uuid4().hex}",
        intent=state_intent,
        context=state_context,
        permissions=Permissions(
            allowed_actions=allowed_actions,
            max_tool_calls=max_tool_calls,
        ),
        signature_algo="Ed25519",
        signature="",
        public_key=source_identity.public_key_pem,
    )


def create_envelope(packet: SignedTaskPacket) -> DelegationEnvelope:
    chain = DelegationChain(
        packet_ids=[packet.packet_id],
        agents=[packet.from_agent],
    )
    return DelegationEnvelope(packet=packet, chain=chain)


def process_framework_handoff(
    source_identity: AgentIdentity,
    target_agent_id: str,
    state_intent: str,
    state_context: dict,
    allowed_actions: list[str] | None = None,
    max_tool_calls: int = 5,
):
    packet = create_packet(
        source_identity=source_identity,
        target_agent_id=target_agent_id,
        state_intent=state_intent,
        state_context=state_context,
        allowed_actions=allowed_actions,
        max_tool_calls=max_tool_calls,
    )

    signed_packet = sign_packet(packet, source_identity)
    envelope = create_envelope(signed_packet)
    decision = process_handoff(envelope.packet)

    if decision.decision == "ACCEPT":
        envelope.chain.add_handoff(signed_packet.packet_id, target_agent_id)

    return {
        "packet": signed_packet,
        "envelope": envelope,
        "decision": decision,
    }
