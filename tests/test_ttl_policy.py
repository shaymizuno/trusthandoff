from datetime import datetime, timezone, timedelta

import pytest

from trusthandoff.decorators import signed_task
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


def test_from_task_computes_write_ttl():
    issued = datetime.now(timezone.utc)

    packet = SignedTaskPacket.from_task(
        task=write_task,
        packet_id="p1",
        task_id="t1",
        from_agent="a",
        to_agent="b",
        nonce="n",
        intent="mutate_record",
        permissions=Permissions(),
        signature_algo="algo",
        signature="sig",
        public_key="pk",
        issued_at=issued,
    )

    ttl = (packet.expires_at - packet.issued_at).total_seconds()
    assert 115 <= ttl <= 125
    assert packet.risk_level == "write"
    assert packet.ttl_seconds == 120


def test_from_task_computes_read_ttl():
    issued = datetime.now(timezone.utc)

    packet = SignedTaskPacket.from_task(
        task=read_task,
        packet_id="p2",
        task_id="t2",
        from_agent="a",
        to_agent="b",
        nonce="n",
        intent="read_record",
        permissions=Permissions(),
        signature_algo="algo",
        signature="sig",
        public_key="pk",
        issued_at=issued,
    )

    ttl = (packet.expires_at - packet.issued_at).total_seconds()
    assert 895 <= ttl <= 905
    assert packet.risk_level == "read"
    assert packet.ttl_seconds == 900


def test_packet_rejects_wrong_ttl_for_write():
    issued = datetime.now(timezone.utc)

    with pytest.raises(ValueError):
        SignedTaskPacket(
            packet_id="p3",
            task_id="t3",
            from_agent="a",
            to_agent="b",
            issued_at=issued,
            expires_at=issued + timedelta(seconds=999),  # wrong for write
            nonce="n",
            intent="mutate_record",
            permissions=Permissions(),
            signature_algo="algo",
            signature="sig",
            public_key="pk",
            risk_level="write",
        )
