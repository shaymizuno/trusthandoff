from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentRegistry,
    DelegationChain,
    DelegationEnvelope,
    SignedTaskPacket,
    verify_envelope,
)
from trusthandoff.packet import Permissions
import trusthandoff.handoff as handoff

handoff.verify_packet = lambda packet: True

def build_packet(agent_id, key, nonce):
    return SignedTaskPacket(
        packet_id="pkt-1",
        task_id="task-1",
        from_agent=agent_id,
        to_agent="agent-beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        nonce=nonce,
        intent="test",
        context={},
        permissions=Permissions(
            allowed_actions=["read"],
            max_tool_calls=1,
        ),
        signature_algo="Ed25519",
        signature="demo",
        public_key=key,
    )


def test_replay_packet_rejected():
    registry = AgentRegistry()

    agent_id = "agent-alpha"
    key = "demo-key"

    registry.register(agent_id, key)

    packet = build_packet(agent_id, key, "nonce-1")

    envelope = DelegationEnvelope(
        packet=packet,
        chain=DelegationChain(
            packet_ids=[packet.packet_id],
            agents=[packet.from_agent],
        ),
    )

    result1 = verify_envelope(envelope, registry=registry)
    result2 = verify_envelope(envelope, registry=registry)

    assert result1.decision != "REJECT"
    assert result2.reason == "replay_detected"
