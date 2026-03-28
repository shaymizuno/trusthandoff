from trusthandoff.adapters.adapter_autogen import TrustHandoffAutoGenAdapter


class MockIdentity:
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.agent_id = "agent-test"

        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


def test_autogen_success():
    identity = MockIdentity()
    adapter = TrustHandoffAutoGenAdapter(identity)

    def node(state):
        return {"value": 42}

    wrapped = adapter.wrap_node(node)

    output = wrapped({"packet_id": "pk-1"})

    assert output["attestation"] is not None
    assert output["result"]["value"] == 42
    assert adapter.verify_node_output(output, identity.public_key_pem)


def test_autogen_error_is_attested():
    identity = MockIdentity()
    adapter = TrustHandoffAutoGenAdapter(identity)

    def node(state):
        raise RuntimeError("boom")

    wrapped = adapter.wrap_node(node)

    output = wrapped({"packet_id": "pk-2"})

    assert output["attestation"] is not None
    assert output["result"]["error"] == "boom"
    assert output["result"]["error_type"] == "RuntimeError"
    assert output["attestation"] is not None

