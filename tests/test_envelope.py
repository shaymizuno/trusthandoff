from datetime import datetime, timedelta, timezone

from trusthandoff import (
    DelegationChain,
    DelegationEnvelope,
    Permissions,
    SignedTaskPacket,
)


def test_delegation_envelope_holds_packet_and_chain():
    packet = SignedTaskPacket(
        packet_id="pk_env_001",
        task_id="task_env_001",
        from_agent="agent:planner:alpha",
        to_agent="agent:research:beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-env-001",
        intent="Envelope test",
        context={"company": "Example Corp"},
        permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key="demo-public-key",
    )

    chain = DelegationChain(
        packet_ids=["pk_env_001"],
        agents=["agent:planner:alpha"],
    )

    envelope = DelegationEnvelope(
        packet=packet,
        chain=chain,
    )

    assert envelope.packet.packet_id == "pk_env_001"
    assert envelope.chain.packet_ids == ["pk_env_001"]
    assert envelope.chain.agents == ["agent:planner:alpha"]
