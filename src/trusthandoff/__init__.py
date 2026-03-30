from .chain import DelegationChain
from .decision import PacketDecision
from .depth import within_max_depth
from .envelope import DelegationEnvelope
from .envelope_serialization import envelope_from_dict, envelope_to_dict
from .handoff import process_handoff
from .identity import AgentIdentity
from .loop import detects_loop
from .packet import SignedTaskPacket, Permissions, Constraints, Provenance
from .policy import check_permission_narrowing
from .replay import ReplayProtection
from .serialization import packet_from_dict, packet_to_dict
from .signing import sign_packet
from .validation import validate_packet
from .verification import verify_packet
from .middleware import TrustHandoffMiddleware
from .wire import envelope_from_json, envelope_to_json
from .middleware.executor import TrustHandoffExecutor
from .api import verify_envelope
from .hop import DelegationHop
from .chain_validation import validate_delegation_chain
from .agent_registry import AgentRegistry
from .capability import DelegationCapability
from .capability_chain_validation import validate_capability_chain
from .api import verify_capability_chain
from .capability_signing import sign_capability, verify_capability_signature
from .capability_token import encode_capability_token, decode_capability_token
from .capability_envelope import CapabilityTokenEnvelope
from .envelope_security import verify_envelope_security
from .revocation import CapabilityRevocationRegistry
from .revocation_validation import is_chain_revoked
from .authorization import is_action_authorized
from .execution_control import (
    execute_authorized_action,
    execute_packet_authorized_action,
)
from .capability_propagation import derive_capability_token
from .packet_propagation import derive_packet_with_capability
from .identity import AgentIdentity
from .revalidation import RevalidationWatcher

# Attestation (v0.3 core)
from .attestation import (
    ExecutionAttestation,
    create_attestation,
    verify_attestation,
    canonical_json_hash,
    validate_attestation_payload,
)
# Errors.py
from .errors import (
    TrustHandoffError,
    AttestationError,
    VerificationError,
    ReplayAttackError,
    InvalidSignatureError,
    PublicKeyMismatchError,
    PayloadValidationError,
    CanonicalizationError,
    CapabilityError,
    StaleCapabilityError,
    RevocationConsistencyError,
    AdapterError,
    MissingPacketIDError,
    MiddlewareExecutionError,
)


__all__ = [
    "DelegationChain",
    "DelegationHop",
    "PacketDecision",
    "DelegationEnvelope",
    "envelope_to_dict",
    "envelope_from_dict",
    "envelope_to_json",
    "envelope_from_json",
    "process_handoff",
    "AgentIdentity",
    "TrustHandoffExecutor",
    "TrustHandoffMiddleware",
    "detects_loop",
    "within_max_depth",
    "SignedTaskPacket",
    "Permissions",
    "Constraints",
    "Provenance",
    "check_permission_narrowing",
    "ReplayProtection",
    "packet_to_dict",
    "packet_from_dict",
    "sign_packet",
    "verify_packet",
    "validate_capability_chain",
    "validate_delegation_chain",
    "validate_packet",
    "verify_envelope",
    "AgentRegistry",
    "DelegationCapability",
    "verify_capability_chain",
    "sign_capability",
    "verify_capability_signature",
    "encode_capability_token",
    "decode_capability_token",
    "CapabilityTokenEnvelope",
    "verify_envelope_security",
    "CapabilityRevocationRegistry",
    "is_chain_revoked",
    "is_action_authorized",
    "execute_authorized_action",
    "execute_packet_authorized_action",
    "derive_capability_token",
    "derive_packet_with_capability",
    "AgentIdentity",
    # Attestation
    "ExecutionAttestation",
    "create_attestation",
    "verify_attestation",
    "canonical_json_hash",
    "validate_attestation_payload",
    # Errors.py
    "TrustHandoffError",
    "AttestationError",
    "VerificationError",
    "ReplayAttackError",
    "InvalidSignatureError",
    "PublicKeyMismatchError",
    "PayloadValidationError",
    "CanonicalizationError",
    "CapabilityError",
    "StaleCapabilityError",
    "RevocationConsistencyError",
    "AdapterError",
    "MissingPacketIDError",
    "MiddlewareExecutionError",
    # Watcher
    "RevalidationWatcher",
]

# Stable public core surface for v0.3
CORE_API = [
    "SignedTaskPacket",
    "PacketDecision",
    "sign_packet",
    "verify_packet",
    "process_handoff",
    "ExecutionAttestation",
    "create_attestation",
    "verify_attestation",
    "canonical_json_hash",
    "validate_attestation_payload",
]
