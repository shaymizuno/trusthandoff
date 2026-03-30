"""
Tests for registry-backed public_key binding in verify_packet and validate_packet.

Security invariant: packet.public_key must be cross-checked against the
AgentRegistry before trusting it. A self-reported key with no registry
backing is not a trust anchor.
"""
import pytest
from datetime import datetime, timezone, timedelta

from trusthandoff import (
    AgentIdentity,
    AgentRegistry,
    Permissions,
    SignedTaskPacket,
    sign_packet,
    verify_packet,
    validate_packet,
    PublicKeyMismatchError,
)


def _make_signed_packet(identity: AgentIdentity) -> SignedTaskPacket:
    packet = SignedTaskPacket(
        packet_id="pk-reg-001",
        task_id="task-reg-001",
        from_agent=identity.agent_id,
        to_agent="agent:receiver",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-reg-001",
        intent="registry binding test",
        permissions=Permissions(allowed_actions=["read"]),
        signature_algo="Ed25519",
        signature="",
        public_key=identity.public_key_pem,
    )
    return sign_packet(packet, identity)


# ---------------------------------------------------------------------------
# verify_packet — with registry
# ---------------------------------------------------------------------------

def test_verify_packet_with_registry_accepts_registered_key():
    identity = AgentIdentity.generate()
    registry = AgentRegistry()
    registry.register(identity.agent_id, identity.public_key_pem)

    packet = _make_signed_packet(identity)
    assert verify_packet(packet, registry=registry) is True


def test_verify_packet_with_registry_raises_on_key_mismatch():
    identity = AgentIdentity.generate()
    other_identity = AgentIdentity.generate()
    registry = AgentRegistry()
    # Register a different key for this agent_id
    registry.register(identity.agent_id, other_identity.public_key_pem)

    packet = _make_signed_packet(identity)

    with pytest.raises(PublicKeyMismatchError) as exc_info:
        verify_packet(packet, registry=registry)

    assert exc_info.value.agent_id == identity.agent_id
    assert exc_info.value.detail == "key_mismatch"


def test_verify_packet_with_registry_raises_when_agent_not_registered():
    identity = AgentIdentity.generate()
    registry = AgentRegistry()  # empty — agent never registered

    packet = _make_signed_packet(identity)

    with pytest.raises(PublicKeyMismatchError) as exc_info:
        verify_packet(packet, registry=registry)

    assert exc_info.value.agent_id == identity.agent_id
    assert exc_info.value.detail == "not_registered"


def test_verify_packet_without_registry_unchanged():
    """No registry → existing behaviour: verify signature only."""
    identity = AgentIdentity.generate()
    packet = _make_signed_packet(identity)
    assert verify_packet(packet) is True


# ---------------------------------------------------------------------------
# validate_packet — with registry
# ---------------------------------------------------------------------------

def test_validate_packet_with_registry_accepts_registered_key():
    identity = AgentIdentity.generate()
    registry = AgentRegistry()
    registry.register(identity.agent_id, identity.public_key_pem)

    packet = _make_signed_packet(identity)
    result = validate_packet(packet, registry=registry)

    assert result.is_valid is True


def test_validate_packet_with_registry_rejects_key_mismatch():
    identity = AgentIdentity.generate()
    other_identity = AgentIdentity.generate()
    registry = AgentRegistry()
    registry.register(identity.agent_id, other_identity.public_key_pem)

    packet = _make_signed_packet(identity)
    result = validate_packet(packet, registry=registry)

    assert result.is_valid is False
    assert result.reason == "public_key_mismatch"


def test_validate_packet_with_registry_rejects_unregistered_agent():
    identity = AgentIdentity.generate()
    registry = AgentRegistry()  # empty

    packet = _make_signed_packet(identity)
    result = validate_packet(packet, registry=registry)

    assert result.is_valid is False
    assert result.reason == "public_key_mismatch"


def test_validate_packet_without_registry_unchanged():
    """No registry → existing behaviour: no binding check."""
    identity = AgentIdentity.generate()
    packet = _make_signed_packet(identity)
    result = validate_packet(packet)

    assert result.is_valid is True


# ---------------------------------------------------------------------------
# PublicKeyMismatchError is a VerificationError
# ---------------------------------------------------------------------------

def test_public_key_mismatch_error_is_verification_error():
    from trusthandoff import VerificationError
    err = PublicKeyMismatchError("agent:foo", "key_mismatch")
    assert isinstance(err, VerificationError)
    assert "agent:foo" in str(err)
    assert "key_mismatch" in str(err)
