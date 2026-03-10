from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentRegistry,
    DelegationCapability,
    verify_capability_chain,
)
from trusthandoff.packet import Permissions


def test_verify_capability_chain_accepts_valid_registered_chain():
    registry = AgentRegistry()
    registry.register("agent:planner:alpha", "key1")
    registry.register("agent:research:beta", "key2")
    registry.register("agent:analyst:gamma", "key3")

    cap1 = DelegationCapability(
        capability_id="cap-1",
        issuer_agent="agent:planner:alpha",
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=5,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=3),
        signature_algo="ed25519",
        signature="sig1",
        public_key="key1",
    )

    cap2 = DelegationCapability(
        capability_id="cap-2",
        issuer_agent="agent:research:beta",
        subject_agent="agent:analyst:gamma",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=3,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        parent_capability_id="cap-1",
        signature_algo="ed25519",
        signature="sig2",
        public_key="key2",
    )

    cap3 = DelegationCapability(
        capability_id="cap-3",
        issuer_agent="agent:analyst:gamma",
        subject_agent="agent:executor:delta",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=1,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        parent_capability_id="cap-2",
        signature_algo="ed25519",
        signature="sig3",
        public_key="key3",
    )

    assert verify_capability_chain([cap1, cap2, cap3], registry=registry) is True


def test_verify_capability_chain_rejects_unknown_issuer():
    registry = AgentRegistry()
    registry.register("agent:planner:alpha", "key1")

    cap1 = DelegationCapability(
        capability_id="cap-1",
        issuer_agent="agent:planner:alpha",
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        signature_algo="ed25519",
        signature="sig1",
        public_key="key1",
    )

    cap2 = DelegationCapability(
        capability_id="cap-2",
        issuer_agent="agent:research:beta",
        subject_agent="agent:analyst:gamma",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=1,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        parent_capability_id="cap-1",
        signature_algo="ed25519",
        signature="sig2",
        public_key="key2",
    )

    assert verify_capability_chain([cap1, cap2], registry=registry) is False
