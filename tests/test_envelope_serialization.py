from datetime import datetime, timedelta, timezone

from trusthandoff import (
    DelegationChain,
    DelegationEnvelope,
    Permissions,
    SignedTaskPacket,
    envelope_from_dict,
    envelope_to_dict,
)


def test_envelope_serialization_roundtrip():
    packet = SignedTaskPacket(
        packet_id="pk_env_serial_001",
        task_id="task_env_serial_001",
        from_agent="agent:planner:alpha",
        to_agent="agent:research:beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-env-serial-001",
        intent="Serialize envelope",
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
        packet_ids=["pk_env_serial_001"],
        agents=["agent:planner:alpha"],
    )

    envelope = DelegationEnvelope(
        packet=packet,
        chain=chain,
    )

    data = envelope_to_dict(envelope)
    rebuilt_envelope = envelope_from_dict(data)

    assert rebuilt_envelope.packet.packet_id == envelope.packet.packet_id
    assert rebuilt_envelope.packet.intent == envelope.packet.intent
    assert rebuilt_envelope.chain.packet_ids == envelope.chain.packet_ids
    assert rebuilt_envelope.chain.agents == envelope.chain.agents
