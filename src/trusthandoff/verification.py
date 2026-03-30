import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .packet import SignedTaskPacket


def verify_packet(packet: SignedTaskPacket) -> bool:
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
