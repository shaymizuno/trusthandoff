import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from trusthandoff.adapters.adapter_langgraph import TrustHandoffLangGraphAdapter


class MockIdentity:
    def __init__(self):
        self.agent_id = "agent-test"
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()

        pem = self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_pem = pem.decode()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def test_langgraph_adapter_honest_roundtrip():
    identity = MockIdentity()
    adapter = TrustHandoffLangGraphAdapter(identity)

    def node(state):
        return {"answer": "42"}

    wrapped = adapter.wrap_node(node)
    output = wrapped({"packet_id": "pk-1"})

    assert output["attestation"] is not None
    assert output["result"] == {"answer": "42"}
    assert adapter.verify_node_output(output, identity.public_key_pem)


def test_langgraph_adapter_node_error_is_attested():
    identity = MockIdentity()
    adapter = TrustHandoffLangGraphAdapter(identity)

    def node(state):
        raise RuntimeError("boom")

    wrapped = adapter.wrap_node(node)
    output = wrapped({"packet_id": "pk-2"})

    assert output["attestation"] is not None
    assert output["result"]["error"] == "boom"
    assert output["result"]["error_type"] == "RuntimeError"
    assert output["attestation"] is not None


def test_langgraph_adapter_missing_packet_id_raises():
    identity = MockIdentity()
    adapter = TrustHandoffLangGraphAdapter(identity)

    def node(state):
        return {"answer": "42"}

    wrapped = adapter.wrap_node(node)

    with pytest.raises(ValueError):
        wrapped({})


def test_langgraph_adapter_programming_error_not_swallowed():
    identity = MockIdentity()
    adapter = TrustHandoffLangGraphAdapter(identity)

    def node(state):
        return {"score": 1.5}  # float forbidden by attestation payload validation

    wrapped = adapter.wrap_node(node)

    with pytest.raises(TypeError):
        wrapped({"packet_id": "pk-3"})


def test_langgraph_adapter_verify_serialized_attestation():
    identity = MockIdentity()
    adapter = TrustHandoffLangGraphAdapter(identity)

    def node(state):
        return {"answer": "serialized"}

    wrapped = adapter.wrap_node(node)
    output = wrapped({"packet_id": "pk-4"})

    serialized_output = {
        "result": output["result"],
        "attestation": output["attestation"].model_dump(),
    }

    assert adapter.verify_node_output(serialized_output, identity.public_key_pem)


def test_langgraph_adapter_verify_rejects_stale_attestation():
    identity = MockIdentity()
    adapter = TrustHandoffLangGraphAdapter(identity)

    def node(state):
        return {"answer": "42"}

    wrapped = adapter.wrap_node(node)
    output = wrapped({"packet_id": "pk-5"})

    stale_now = output["attestation"].timestamp_ms + 600_000

    assert not adapter.verify_node_output(
        output,
        identity.public_key_pem,
        max_age_seconds=300,
        current_timestamp_ms=stale_now,
    )


def test_langgraph_adapter_seen_nonces_blocks_replay():
    identity = MockIdentity()
    adapter = TrustHandoffLangGraphAdapter(identity)

    def node(state):
        return {"answer": "42"}

    wrapped = adapter.wrap_node(node)
    output = wrapped({"packet_id": "pk-6"})

    seen_nonces = set()

    assert adapter.verify_node_output(
        output,
        identity.public_key_pem,
        seen_nonces=seen_nonces,
    )

    assert not adapter.verify_node_output(
        output,
        identity.public_key_pem,
        seen_nonces=seen_nonces,
    )
