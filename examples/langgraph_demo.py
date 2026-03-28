import logging
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from trusthandoff.adapters.adapter_langgraph import TrustHandoffLangGraphAdapter

GREEN = "\033[92m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

def verdict(ok: bool) -> str:
    return GREEN + "✅" + RESET if ok else RED + "❌" + RESET

class MockIdentity:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


def planner_node(state):
    return {
        "step": "planner",
        "task": "Summarize the repository status",
        "status": "ready_for_handoff",
        "target_agent": "researcher",
    }


def researcher_node(state):
    return {
        "step": "researcher",
        "summary": "Repository is clean and attested",
        "status": "completed",
    }


def short_hash(value: str) -> str:
    return value[:12] + "..."


def short_nonce(value: int) -> str:
    return hex(value)[:14] + "..."


def print_output(title: str, output: dict):
    result = output["result"]
    att = output["attestation"]

    print(title)
    print("result:")
    for key, value in result.items():
        print(f"  {key}: {value}")

    if att is not None:
        print("attestation:")
        print(f"  status: {att.status}")
        print(f"  hash:   {short_hash(att.outcome_hash)}")
        print(f"  nonce:  {short_nonce(att.nonce)}")
    else:
        print("attestation: None")
    print()


def main():
    logging.getLogger("trusthandoff.adapters.adapter_langgraph").setLevel(logging.ERROR)

    identity = MockIdentity("agent:langgraph-demo")
    adapter = TrustHandoffLangGraphAdapter(identity)

    print("=== TRUSTHANDOFF × LANGGRAPH DEMO ===")
    print()

    wrapped_planner = adapter.wrap_node(planner_node)
    planner_output = wrapped_planner({"packet_id": "pk-langgraph-001"})
    planner_ok = adapter.verify_node_output(
        planner_output,
        identity.public_key_pem,
        seen_nonces=set(),
    )

    print_output("1) PLANNER NODE", planner_output)
    print("verification:", verdict(planner_ok))
    print()

    wrapped_researcher = adapter.wrap_node(researcher_node)
    researcher_output = wrapped_researcher({"packet_id": "pk-langgraph-002"})
    researcher_ok = adapter.verify_node_output(
        researcher_output,
        identity.public_key_pem,
        seen_nonces=set(),
    )

    print_output("2) RESEARCHER NODE", researcher_output)
    print("verification:", verdict(researcher_ok))
    print()

    print("\n--- ATTACK: tampering output ---")

    tampered_output = {
        "result": {
            "step": "researcher",
            "summary": "Repository drained and exfiltrated",
            "status": "completed",
        },
        "attestation": researcher_output["attestation"],
    }

    tampered_ok = adapter.verify_node_output(
        tampered_output,
        identity.public_key_pem,
        seen_nonces=set(),
    )

    print_output("3) TAMPERED HANDOFF", tampered_output)
    print("verification:", verdict(tampered_ok))
    print()

    print("\n--- ATTACK: replaying output ---")

    replay_ok = adapter.verify_node_output(
        researcher_output,
        identity.public_key_pem,
        seen_nonces={(researcher_output["attestation"].agent_pubkey_fingerprint, researcher_output["attestation"].nonce)},
    )

    print_output("4) REPLAYED HANDOFF", researcher_output)
    print("verification:", verdict(replay_ok))
    print()

    print("TAKEAWAY")
    print("- node output can be attested at the handoff boundary")
    print("- valid node output verifies")
    print("- modified node output is rejected")

if __name__ == "__main__":
    main()
