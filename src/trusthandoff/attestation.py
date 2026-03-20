import base64
import json
import secrets
import time
from hashlib import sha256
from typing import Any, Literal, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field


DOMAIN_SEPARATOR = b"TRUSTHANDOFF_EXEC_ATTEST_V3\x00"
VERSION_BYTE = b"\x01"

AttestationStatus = Literal["OK", "ERROR", "PARTIAL", "REJECTED", "TIMEOUT"]


class ExecutionAttestation(BaseModel):
    packet_id: str
    status: AttestationStatus
    outcome_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    nonce: int = Field(default_factory=lambda: secrets.randbits(128), ge=0)
    timestamp_ms: int = Field(default_factory=lambda: int(time.time() * 1000), ge=0)
    signed_by: str
    agent_pubkey_fingerprint: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    signature: str
    reason_hash: Optional[str] = Field(None, pattern=r"^[0-9a-f]{64}$")

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )


def validate_attestation_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): validate_attestation_payload(v) for k, v in value.items()}

    if isinstance(value, list):
        return [validate_attestation_payload(v) for v in value]

    if isinstance(value, float):
        raise TypeError("Floats are not allowed in canonical attestation payloads")

    if isinstance(value, (int, str, bool)) or value is None:
        return value

    raise TypeError(f"Unsupported type in canonical JSON: {type(value)}")


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    safe_data = validate_attestation_payload(data)
    return json.dumps(
        safe_data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_json_hash(data: Optional[dict[str, Any]]) -> Optional[str]:
    if data is None:
        return None
    return sha256(canonical_json_bytes(data)).hexdigest()


def _framed_payload(
    packet_id: bytes,
    outcome_hash: bytes,
    status: bytes,
    nonce: int,
    timestamp_ms: int,
    agent_pubkey_fingerprint: bytes,
    reason_hash: Optional[bytes] = None,
) -> bytes:
    fields = [
        packet_id,
        outcome_hash,
        status,
        nonce.to_bytes(16, "big", signed=False),
        timestamp_ms.to_bytes(8, "big", signed=False),
        agent_pubkey_fingerprint,
    ]

    if reason_hash is not None:
        fields.append(reason_hash)

    framed = b"".join(
        len(field).to_bytes(4, "big") + field for field in fields
    )
    return DOMAIN_SEPARATOR + VERSION_BYTE + framed


def _pubkey_fingerprint_from_identity(identity) -> str:
    public_key = serialization.load_pem_public_key(
        identity.public_key_pem.encode("utf-8")
    )

    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("Expected an Ed25519 public key")

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha256(public_key_bytes).hexdigest()


def create_attestation(
    packet_id: str,
    result: dict[str, Any],
    identity,
    status: AttestationStatus = "OK",
    nonce: Optional[int] = None,
    timestamp_ms: Optional[int] = None,
    reason: Optional[dict[str, Any]] = None,
) -> ExecutionAttestation:
    nonce_value = secrets.randbits(128) if nonce is None else nonce
    timestamp_value = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms

    if nonce_value < 0 or timestamp_value < 0:
        raise ValueError("nonce and timestamp_ms must be non-negative")

    if timestamp_value >= (1 << 64):
        raise ValueError("timestamp_ms exceeds 64-bit unsigned range")

    if timestamp_value < 1577836800000:
        raise ValueError("timestamp_ms before reasonable epoch")

    outcome_hash_str = canonical_json_hash(result)
    if outcome_hash_str is None:
        raise ValueError("result must not be None")

    reason_hash_str = canonical_json_hash(reason)
    pubkey_fingerprint = _pubkey_fingerprint_from_identity(identity)

    payload = _framed_payload(
        packet_id=packet_id.encode(),
        outcome_hash=bytes.fromhex(outcome_hash_str),
        status=status.encode(),
        nonce=nonce_value,
        timestamp_ms=timestamp_value,
        agent_pubkey_fingerprint=bytes.fromhex(pubkey_fingerprint),
        reason_hash=bytes.fromhex(reason_hash_str) if reason_hash_str else None,
    )

    signature = identity.sign(payload)
    signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    return ExecutionAttestation(
        packet_id=packet_id,
        status=status,
        outcome_hash=outcome_hash_str,
        nonce=nonce_value,
        timestamp_ms=timestamp_value,
        signed_by=identity.agent_id,
        agent_pubkey_fingerprint=pubkey_fingerprint,
        signature=signature_b64,
        reason_hash=reason_hash_str,
    )


# IMPORTANT:
# Verifier MUST track seen (agent_pubkey_fingerprint, nonce) within freshness window
# to prevent replay attacks.


def verify_attestation(
    attestation: ExecutionAttestation,
    public_key_pem: str,
    expected_outcome_hash: Optional[str] = None,
    result: Optional[dict[str, Any]] = None,
    expected_reason_hash: Optional[str] = None,
    reason: Optional[dict[str, Any]] = None,
    max_age_seconds: int = 300,
    now_ms: Optional[int] = None,
) -> bool:
    if expected_outcome_hash is None:
        if result is None:
            raise ValueError("Provide expected_outcome_hash or result")
        expected_outcome_hash = canonical_json_hash(result)

    if expected_reason_hash is None and reason is not None:
        expected_reason_hash = canonical_json_hash(reason)

    if expected_outcome_hash != attestation.outcome_hash:
        return False

    if (expected_reason_hash or None) != (attestation.reason_hash or None):
        return False

    now_ms_value = int(time.time() * 1000) if now_ms is None else now_ms

    if attestation.timestamp_ms > now_ms_value + 30_000:
        return False

    if attestation.timestamp_ms < now_ms_value - max_age_seconds * 1000:
        return False

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
    except Exception:
        return False

    if not isinstance(public_key, Ed25519PublicKey):
        return False

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = sha256(pub_bytes).hexdigest()

    if fingerprint != attestation.agent_pubkey_fingerprint:
        return False

    try:
        padding = "=" * (-len(attestation.signature) % 4)
        sig = base64.urlsafe_b64decode(attestation.signature + padding)
    except Exception:
        return False

    payload = _framed_payload(
        packet_id=attestation.packet_id.encode(),
        outcome_hash=bytes.fromhex(attestation.outcome_hash),
        status=attestation.status.encode(),
        nonce=attestation.nonce,
        timestamp_ms=attestation.timestamp_ms,
        agent_pubkey_fingerprint=bytes.fromhex(attestation.agent_pubkey_fingerprint),
        reason_hash=bytes.fromhex(attestation.reason_hash) if attestation.reason_hash else None,
    )

    try:
        public_key.verify(sig, payload)
        return True
    except Exception:
        return False
