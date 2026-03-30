import base64
import json
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .agent_registry import AgentRegistry
from .errors import PublicKeyMismatchError
from .packet import SignedTaskPacket


def _check_registry_binding(packet: SignedTaskPacket, registry: AgentRegistry) -> None:
    """
    Assert that packet.public_key matches the canonical key in the registry
    for packet.from_agent.

    Raises PublicKeyMismatchError — never returns a bool, never swallows errors.
    Callers decide whether to propagate or convert to a validation result.
    """
    registered_key = registry.resolve(packet.from_agent)
    if registered_key is None:
        raise PublicKeyMismatchError(packet.from_agent, "not_registered")
    if packet.public_key != registered_key:
        raise PublicKeyMismatchError(packet.from_agent, "key_mismatch")


def verify_packet(packet: SignedTaskPacket, registry: Optional[AgentRegistry] = None) -> bool:
    if registry is not None:
        _check_registry_binding(packet, registry)

    public_key = serialization.load_pem_public_key(
        packet.public_key.encode("utf-8")
    )

    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("Expected an Ed25519 public key")

    payload = json.dumps(
        packet.model_dump(exclude={"signature"}, mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    signature = base64.b64decode(packet.signature.encode("utf-8"))

    try:
        public_key.verify(signature, payload)
        return True
    except InvalidSignature:
        return False
