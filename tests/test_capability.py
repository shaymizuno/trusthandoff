from datetime import datetime, timedelta, timezone
from trusthandoff import DelegationCapability
from trusthandoff.packet import Permissions


def test_create_capability():
    cap = DelegationCapability(
        capability_id="cap-1",
        issuer_agent="agent:planner:alpha",
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="ed25519",
        signature="fake-signature",
        public_key="fake-key",
    )

    assert cap.issuer_agent == "agent:planner:alpha"
    assert cap.subject_agent == "agent:research:beta"
    assert cap.capability_id == "cap-1"
