import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .identity import AgentIdentity
from .packet import SignedTaskPacket


def sign_packet(packet: SignedTaskPacket, identity: AgentIdentity) -> SignedTaskPacket:
    private_key = serialization.load_pem_private_key(
        identity.private_key_pem.encode("utf-8"),
        password=None,
    )

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Expected an Ed25519 private key")

    payload = json.dumps(
        packet.model_dump(exclude={"signature"}, mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    signature = private_key.sign(payload)
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    signed_packet = packet.model_copy(update={"signature": signature_b64})
    return signed_packet
