from datetime import datetime, timezone, timedelta

import pytest

from trusthandoff.decorators import signed_task, DEFAULT_POLICY
from trusthandoff.packet import SignedTaskPacket, Permissions


@signed_task(risk_level="write")
def write_task():
    pass


@signed_task(risk_level="read")
def read_task():
    pass


def test_decorator_metadata():
    assert write_task._trusthandoff_metadata["risk_level"] == "write"
    assert write_task._trusthandoff_metadata["ttl_seconds"] == 120

    assert read_task._trusthandoff_metadata["risk_level"] == "read"
    assert read_task._trusthandoff_metadata["ttl_seconds"] == 900


def test_packet_ttl_auto_compute_from_risk():
    issued = datetime.now(timezone.utc)

    packet = SignedTaskPacket(
        packet_id="p1",
        task_id="t1",
        from_agent="a",
        to_agent="b",
        issued_at=issued,
        expires_at=None,  # ← key: let model compute
        nonce="n",
        intent="test",
        permissions=Permissions(),
        signature_algo="algo",
        signature="sig",
        public_key="pk",
        risk_level="write",
    )

    ttl = (packet.expires_at - packet.issued_at).total_seconds()
    assert 115 <= ttl <= 125


def test_packet_rejects_wrong_ttl():
    issued = datetime.now(timezone.utc)

    with pytest.raises(ValueError):
        SignedTaskPacket(
            packet_id="p2",
            task_id="t2",
            from_agent="a",
            to_agent="b",
            issued_at=issued,
            expires_at=issued + timedelta(seconds=999),  # WRONG
            nonce="n",
            intent="test",
            permissions=Permissions(),
            signature_algo="algo",
            signature="sig",
            public_key="pk",
            risk_level="write",
        )
