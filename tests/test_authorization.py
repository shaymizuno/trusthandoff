from datetime import datetime, timedelta, timezone

from trusthandoff import DelegationCapability, is_action_authorized
from trusthandoff.packet import Permissions


def test_is_action_authorized_accepts_allowed_action():
    capability = DelegationCapability(
        capability_id="cap-auth-1",
        issuer_agent="agent:planner:alpha",
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="sig",
        public_key="key",
    )

    assert is_action_authorized(capability, "search", tool_calls_used=1) is True


def test_is_action_authorized_rejects_disallowed_action():
    capability = DelegationCapability(
        capability_id="cap-auth-2",
        issuer_agent="agent:planner:alpha",
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read"],
            max_tool_calls=3,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="sig",
        public_key="key",
    )

    assert is_action_authorized(capability, "write", tool_calls_used=0) is False


def test_is_action_authorized_rejects_tool_call_limit():
    capability = DelegationCapability(
        capability_id="cap-auth-3",
        issuer_agent="agent:planner:alpha",
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="sig",
        public_key="key",
    )

    assert is_action_authorized(capability, "search", tool_calls_used=2) is False
