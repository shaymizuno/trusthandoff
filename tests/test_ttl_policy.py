from datetime import datetime, timezone, timedelta
from trusthandoff.packet import SignedTaskPacket, Permissions


def test_ttl_write_enforced():
    issued = datetime.now(timezone.utc)

    packet = SignedTaskPacket(
        packet_id="p1",
        task_id="t1",
        from_agent="a",
        to_agent="b",
        issued_at=issued,
        expires_at=issued + timedelta(seconds=120),
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


def test_ttl_reject_mismatch():
    issued = datetime.now(timezone.utc)

    try:
        SignedTaskPacket(
            packet_id="p2",
            task_id="t2",
            from_agent="a",
            to_agent="b",
            issued_at=issued,
            expires_at=issued + timedelta(seconds=999),  # WRONG TTL
            nonce="n",
            intent="test",
            permissions=Permissions(),
            signature_algo="algo",
            signature="sig",
            public_key="pk",
            risk_level="write",
        )
        assert False, "Should have failed"
    except ValueError:
        assert True
