from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    DelegationCapability,
    decode_capability_token,
    derive_capability_token,
)
from trusthandoff.packet import Permissions


def test_derive_capability_token_propagates_restricted_authority():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()
    analyst = AgentIdentity.generate()

    parent = DelegationCapability(
        capability_id="cap-parent-1",
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

    token = derive_capability_token(
        parent=parent,
        child_capability_id="cap-child-1",
        child_subject_agent=analyst.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        private_key_pem=research.private_key_pem,
    )

    child = decode_capability_token(token)

    assert child.capability_id == "cap-child-1"
    assert child.issuer_agent == research.agent_id
    assert child.subject_agent == analyst.agent_id
    assert child.parent_capability_id == "cap-parent-1"
    assert child.delegated_permissions.allowed_actions == ["search"]
    assert child.delegated_permissions.max_tool_calls == 2
