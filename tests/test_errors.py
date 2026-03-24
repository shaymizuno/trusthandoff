from trusthandoff import (
    TrustHandoffError,
    AttestationError,
    VerificationError,
    ReplayAttackError,
    InvalidSignatureError,
    PayloadValidationError,
    CanonicalizationError,
    CapabilityError,
    StaleCapabilityError,
    RevocationConsistencyError,
    AdapterError,
    MissingPacketIDError,
    MiddlewareExecutionError,
)


def test_error_hierarchy():
    assert issubclass(AttestationError, TrustHandoffError)
    assert issubclass(VerificationError, TrustHandoffError)
    assert issubclass(ReplayAttackError, VerificationError)
    assert issubclass(InvalidSignatureError, VerificationError)
    assert issubclass(PayloadValidationError, TrustHandoffError)
    assert issubclass(CanonicalizationError, TrustHandoffError)
    assert issubclass(CapabilityError, TrustHandoffError)
    assert issubclass(StaleCapabilityError, CapabilityError)
    assert issubclass(RevocationConsistencyError, CapabilityError)
    assert issubclass(AdapterError, TrustHandoffError)
    assert issubclass(MissingPacketIDError, AdapterError)
    assert issubclass(MiddlewareExecutionError, AdapterError)


def test_stale_capability_error_fields():
    err = StaleCapabilityError("cap-123", "revoked_mid_task")
    assert err.capability_id == "cap-123"
    assert err.reason == "revoked_mid_task"
    assert "cap-123" in str(err)
    assert "revoked_mid_task" in str(err)


def test_revocation_consistency_error_fields():
    err = RevocationConsistencyError("tok-456", "stale_read")
    assert err.token_id == "tok-456"
    assert err.detail == "stale_read"
    assert "tok-456" in str(err)
    assert "stale_read" in str(err)


def test_missing_packet_id_error_fields():
    err = MissingPacketIDError("custom_packet_id")
    assert err.packet_id_key == "custom_packet_id"
    assert "custom_packet_id" in str(err)
