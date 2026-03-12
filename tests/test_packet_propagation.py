from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    DelegationCapability,
    decode_capability_token,
    derive_packet_with_capability,
)
from trusthandoff.packet import Permissions


def test_derive_packet_with_capability_embeds_child_token():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()
    analyst = AgentIdentity.generate()

    parent_capability = DelegationCapability(
        capability_id="cap-parent-pkt-1",
        issuer_agent=planner.agent_id,
        subject_agent=research.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=5,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        signature_algo="Ed25519",
        signature="",
        public_key=research.public_key_pem,
    )

    packet = derive_packet_with_capability(
        parent_capability=parent_capability,
        child_capability_id="cap-child-pkt-1",
        child_subject_agent=analyst.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        capability_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        private_key_pem=research.private_key_pem,
        packet_id="pkt-child-1",
        task_id="task-child-1",
        from_agent=research.agent_id,
        to_agent=analyst.agent_id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        nonce="nonce-child-1",
        intent="search",
        permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key=research.public_key_pem,
    )

    assert packet.capability_token is not None

    child_capability = decode_capability_token(packet.capability_token)

    assert packet.from_agent == research.agent_id
    assert packet.to_agent == analyst.agent_id
    assert child_capability.capability_id == "cap-child-pkt-1"
    assert child_capability.issuer_agent == research.agent_id
    assert child_capability.subject_agent == analyst.agent_id
    assert child_capability.parent_capability_id == "cap-parent-pkt-1"
