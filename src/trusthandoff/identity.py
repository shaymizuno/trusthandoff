import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


@dataclass
class AgentIdentity:
    agent_id: str
    private_key_pem: str
    public_key_pem: str

    @classmethod
    def generate(cls) -> "AgentIdentity":
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        public_key_hash = hashlib.sha256(public_bytes).digest()
        agent_id = f"agent:{_b64(public_key_hash)[:16]}"

        return cls(
            agent_id=agent_id,
            private_key_pem=private_bytes.decode("utf-8"),
            public_key_pem=public_bytes.decode("utf-8"),
        )
