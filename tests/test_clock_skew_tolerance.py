from datetime import datetime, timedelta, timezone
from importlib import reload
import os

import trusthandoff.validation as validation
from trusthandoff import Permissions, SignedTaskPacket
from trusthandoff.validation import validate_packet


def make_packet(issued_at, expires_at):
    return SignedTaskPacket(
        packet_id="pk-skew",
        task_id="task-skew",
        from_agent="agent:a",
        to_agent="agent:b",
        issued_at=issued_at,
        expires_at=expires_at,
        nonce="nonce-skew",
        intent="search",
        context={"q": "test"},
        permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=1,
        ),
        signature_algo="Ed25519",
        signature="",
        public_key="-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n",
    )


def test_validate_packet_rejects_future_packet_when_issuance_skew_zero():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now + timedelta(seconds=1),
        expires_at=now + timedelta(minutes=10),
    )
    assert validate_packet(
        packet,
        issuance_skew=timedelta(seconds=0),
        expiry_grace=timedelta(seconds=0),
    ) is False


def test_validate_packet_accepts_future_packet_within_issuance_skew():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now + timedelta(seconds=29),
        expires_at=now + timedelta(minutes=10),
    )
    assert validate_packet(
        packet,
        issuance_skew=timedelta(seconds=30),
        expiry_grace=timedelta(seconds=0),
    ) is True


def test_validate_packet_rejects_future_packet_beyond_issuance_skew():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now + timedelta(seconds=31),
        expires_at=now + timedelta(minutes=10),
    )
    assert validate_packet(
        packet,
        issuance_skew=timedelta(seconds=30),
        expiry_grace=timedelta(seconds=0),
    ) is False


def test_validate_packet_rejects_expired_packet_when_expiry_grace_zero():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(seconds=1),
    )
    assert validate_packet(
        packet,
        issuance_skew=timedelta(seconds=30),
        expiry_grace=timedelta(seconds=0),
    ) is False


def test_validate_packet_accepts_recently_expired_packet_within_expiry_grace():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(seconds=9),
    )
    assert validate_packet(
        packet,
        issuance_skew=timedelta(seconds=30),
        expiry_grace=timedelta(seconds=10),
    ) is True


def test_validate_packet_rejects_expired_packet_beyond_expiry_grace():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(seconds=11),
    )
    assert validate_packet(
        packet,
        issuance_skew=timedelta(seconds=30),
        expiry_grace=timedelta(seconds=10),
    ) is False


def test_validate_packet_rejects_malformed_time_window():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now + timedelta(minutes=5),
        expires_at=now + timedelta(minutes=4),
    )
    assert validate_packet(packet) is False


def test_issuance_skew_env_is_capped_at_300(monkeypatch):
    monkeypatch.setenv("TRUSTHANDOFF_ISSUANCE_SKEW", "500")
    monkeypatch.setenv("TRUSTHANDOFF_EXPIRY_GRACE", "0")
    reload(validation)
    assert validation.DEFAULT_ISSUANCE_SKEW_SECONDS == 300


def test_expiry_grace_env_is_capped_at_60(monkeypatch):
    monkeypatch.setenv("TRUSTHANDOFF_ISSUANCE_SKEW", "30")
    monkeypatch.setenv("TRUSTHANDOFF_EXPIRY_GRACE", "500")
    reload(validation)
    assert validation.DEFAULT_EXPIRY_GRACE_SECONDS == 60
