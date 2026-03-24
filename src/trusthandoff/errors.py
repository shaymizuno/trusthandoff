"""
TrustHandoff error definitions.

These exceptions are intentionally minimal and composable.
They allow callers to distinguish failure modes without parsing strings.
"""


class TrustHandoffError(Exception):
    """Base class for all TrustHandoff-related errors."""
    pass


# ---------------------------------------------------------------------
# Attestation / Verification Errors
# ---------------------------------------------------------------------

class AttestationError(TrustHandoffError):
    """Raised when attestation creation fails."""
    pass


class VerificationError(TrustHandoffError):
    """Raised when attestation verification fails."""
    pass


class ReplayAttackError(VerificationError):
    """Raised when a replay attack is detected (nonce reuse)."""
    pass


class InvalidSignatureError(VerificationError):
    """Raised when signature verification fails."""
    pass


# ---------------------------------------------------------------------
# Payload / Protocol Errors
# ---------------------------------------------------------------------

class PayloadValidationError(TrustHandoffError):
    """Raised when payload validation fails."""
    pass


class CanonicalizationError(TrustHandoffError):
    """Raised when canonical JSON encoding fails."""
    pass


# ---------------------------------------------------------------------
# Capability / Revocation Errors
# ---------------------------------------------------------------------

class CapabilityError(TrustHandoffError):
    """Base class for capability and revocation-related failures."""
    pass


class StaleCapabilityError(CapabilityError):
    """
    Raised when a previously valid capability becomes stale during execution.

    Examples:
    - permission revoked mid-task
    - token expired during a long-running job
    - scope changed after initial validation
    """

    def __init__(self, capability_id: str, reason: str = "revoked_or_expired"):
        self.capability_id = capability_id
        self.reason = reason
        super().__init__(f"Stale capability {capability_id}: {reason}")


class RevocationConsistencyError(CapabilityError):
    """
    Raised when revocation state is stale, lagging, or internally inconsistent.

    This does not necessarily prove a capability is invalid, but it means
    the system cannot guarantee correctness of the revocation check.
    """

    def __init__(self, token_id: str, detail: str = "stale_or_inconsistent_revocation_state"):
        self.token_id = token_id
        self.detail = detail
        super().__init__(f"Revocation inconsistency for {token_id}: {detail}")


# ---------------------------------------------------------------------
# Adapter / Middleware Errors
# ---------------------------------------------------------------------

class AdapterError(TrustHandoffError):
    """Base class for adapter-related failures."""
    pass


class MissingPacketIDError(AdapterError):
    """Raised when packet_id is missing in state or input."""

    def __init__(self, packet_id_key: str = "packet_id"):
        self.packet_id_key = packet_id_key
        super().__init__(f"Missing required packet identifier: {packet_id_key}")


class MiddlewareExecutionError(AdapterError):
    """Raised when middleware execution fails unexpectedly."""
    pass
