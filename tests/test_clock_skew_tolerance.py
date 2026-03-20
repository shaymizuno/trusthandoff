from datetime import datetime, timedelta, timezone
from importlib import reload

import trusthandoff.validation as validation
from trusthandoff import Permissions, SignedTaskPacket
from trusthandoff.handoff import process_handoff
from trusthandoff.validation import PacketValidationResult, validate_packet


def make_packet(
    issued_at: datetime,
    expires_at: datetime,
    signature: str = "dmFsaWQtc2lnbmF0dXJl",
) -> SignedTaskPacket:
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
        signature=signature,
        public_key="-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----\n",
    )


def test_validate_packet_accepts_valid_packet():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(seconds=5),
        expires_at=now + timedelta(minutes=5),
    )

    result = validate_packet(packet)

    assert result == PacketValidationResult(True, None)


def test_validate_packet_rejects_malformed_time_window():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now + timedelta(minutes=5),
        expires_at=now + timedelta(minutes=4),
    )

    result = validate_packet(packet)

    assert result == PacketValidationResult(False, "malformed_time_window")


def test_validate_packet_rejects_future_packet_when_issuance_skew_zero():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now + timedelta(seconds=1),
        expires_at=now + timedelta(minutes=10),
    )

    result = validate_packet(
        packet,
        issuance_skew=timedelta(seconds=0),
        expiry_grace=timedelta(seconds=0),
    )

    assert result == PacketValidationResult(False, "issued_in_future")


def test_validate_packet_accepts_future_packet_within_issuance_skew():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now + timedelta(seconds=29),
        expires_at=now + timedelta(minutes=10),
    )

    result = validate_packet(
        packet,
        issuance_skew=timedelta(seconds=30),
        expiry_grace=timedelta(seconds=0),
    )

    assert result == PacketValidationResult(True, None)


def test_validate_packet_rejects_future_packet_beyond_issuance_skew():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now + timedelta(seconds=31),
        expires_at=now + timedelta(minutes=10),
    )

    result = validate_packet(
        packet,
        issuance_skew=timedelta(seconds=30),
        expiry_grace=timedelta(seconds=0),
    )

    assert result == PacketValidationResult(False, "issued_in_future")


def test_validate_packet_rejects_expired_packet_when_expiry_grace_zero():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(seconds=1),
    )

    result = validate_packet(
        packet,
        issuance_skew=timedelta(seconds=30),
        expiry_grace=timedelta(seconds=0),
    )

    assert result == PacketValidationResult(False, "expired")


def test_validate_packet_accepts_recently_expired_packet_within_expiry_grace():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(seconds=9),
    )

    result = validate_packet(
        packet,
        issuance_skew=timedelta(seconds=30),
        expiry_grace=timedelta(seconds=10),
    )

    assert result == PacketValidationResult(True, None)


def test_validate_packet_rejects_expired_packet_beyond_expiry_grace():
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(seconds=11),
    )

    result = validate_packet(
        packet,
        issuance_skew=timedelta(seconds=30),
        expiry_grace=timedelta(seconds=10),
    )

    assert result == PacketValidationResult(False, "expired")


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


def test_process_handoff_emits_accept_audit(monkeypatch):
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(seconds=5),
        expires_at=now + timedelta(minutes=5),
    )
    events = []

    monkeypatch.setattr("trusthandoff.handoff.verify_packet", lambda p: True)
    monkeypatch.setattr(
        "trusthandoff.handoff.validate_packet",
        lambda p: PacketValidationResult(True, None),
    )

    decision = process_handoff(packet, audit_collector=events.append)

    assert decision.decision == "ACCEPT"
    assert events[0]["event"] == "handoff_accepted"
    assert events[0]["packet_id"] == packet.packet_id


def test_process_handoff_emits_invalid_signature_audit(monkeypatch):
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(seconds=5),
        expires_at=now + timedelta(minutes=5),
        signature="bad-signature-preview",
    )
    events = []

    monkeypatch.setattr("trusthandoff.handoff.verify_packet", lambda p: False)

    decision = process_handoff(packet, audit_collector=events.append)

    assert decision.decision == "REJECT"
    assert decision.reason == "Invalid signature"
    assert events[0]["event"] == "handoff_rejected_invalid_signature"
    assert events[0]["details"]["reason"] == "Invalid signature"


def test_process_handoff_emits_invalid_packet_audit(monkeypatch):
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(seconds=1),
    )
    events = []

    monkeypatch.setattr("trusthandoff.handoff.verify_packet", lambda p: True)
    monkeypatch.setattr(
        "trusthandoff.handoff.validate_packet",
        lambda p: PacketValidationResult(False, "expired"),
    )

    decision = process_handoff(packet, audit_collector=events.append)

    assert decision.decision == "REJECT"
    assert decision.reason == "expired"
    assert events[0]["event"] == "handoff_rejected_invalid_packet"
    assert events[0]["details"]["reason"] == "expired"


def test_process_handoff_with_no_audit_collector_still_works(monkeypatch):
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(seconds=5),
        expires_at=now + timedelta(minutes=5),
    )

    monkeypatch.setattr("trusthandoff.handoff.verify_packet", lambda p: True)
    monkeypatch.setattr(
        "trusthandoff.handoff.validate_packet",
        lambda p: PacketValidationResult(True, None),
    )

    decision = process_handoff(packet, audit_collector=None)

    assert decision.decision == "ACCEPT"


def test_process_handoff_ignores_audit_collector_failures(monkeypatch):
    now = datetime.now(timezone.utc)
    packet = make_packet(
        issued_at=now - timedelta(seconds=5),
        expires_at=now + timedelta(minutes=5),
    )

    monkeypatch.setattr("trusthandoff.handoff.verify_packet", lambda p: True)
    monkeypatch.setattr(
        "trusthandoff.handoff.validate_packet",
        lambda p: PacketValidationResult(True, None),
    )

    def broken_collector(_event):
        raise RuntimeError("audit sink down")

    decision = process_handoff(packet, audit_collector=broken_collector)

    assert decision.decision == "ACCEPT"
