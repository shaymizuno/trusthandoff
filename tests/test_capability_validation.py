from datetime import datetime, timedelta, timezone

from trusthandoff import DelegationCapability
from trusthandoff.packet import Permissions
from trusthandoff.capability_validation import validate_capability_derivation


def test_valid_capability_derivation():

    parent = DelegationCapability(
        capability_id="cap-parent",
        issuer_agent="agent:planner:alpha",
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=5
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        signature_algo="ed25519",
        signature="sig",
        public_key="key",
    )

    child = DelegationCapability(
        capability_id="cap-child",
        issuer_agent="agent:research:beta",
        subject_agent="agent:analyst:gamma",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        parent_capability_id="cap-parent",
        signature_algo="ed25519",
        signature="sig",
        public_key="key",
    )

    assert validate_capability_derivation(parent, child)


def test_reject_capability_escalation():

    parent = DelegationCapability(
        capability_id="cap-parent",
        issuer_agent="agent:planner:alpha",
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        signature_algo="ed25519",
        signature="sig",
        public_key="key",
    )

    child = DelegationCapability(
        capability_id="cap-child",
        issuer_agent="agent:research:beta",
        subject_agent="agent:analyst:gamma",
        delegated_permissions=Permissions(
            allowed_actions=["search", "write"],
            max_tool_calls=5
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        parent_capability_id="cap-parent",
        signature_algo="ed25519",
        signature="sig",
        public_key="key",
    )

    assert validate_capability_derivation(parent, child) is False
