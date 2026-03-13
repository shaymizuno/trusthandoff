from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentRegistry,
    DelegationChain,
    DelegationEnvelope,
    PacketDecision,
    SignedTaskPacket,
    verify_envelope,
)
from trusthandoff.packet import Permissions


def test_revoked_agent_packet_rejected():
    registry = AgentRegistry()

    agent_id = "agent-alpha"
    public_key = "demo-key"

    registry.register(agent_id, public_key)
    registry.revoke(agent_id)

    packet = SignedTaskPacket(
        packet_id="pkt-1",
        task_id="task-1",
        from_agent=agent_id,
        to_agent="agent-beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        nonce="nonce-1",
        intent="test-intent",
        context={},
        permissions=Permissions(
            allowed_actions=["read"],
            max_tool_calls=1,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key=public_key,
    )

    envelope = DelegationEnvelope(
        packet=packet,
        chain=DelegationChain(
            packet_ids=[packet.packet_id],
            agents=[packet.from_agent],
        ),
    )

    result = verify_envelope(envelope, registry=registry)

    assert result.decision == "REJECT"
    assert result.reason == "agent_revoked"
