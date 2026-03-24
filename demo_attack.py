import logging
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from adapters.adapter_langgraph import TrustHandoffLangGraphAdapter


RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


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


def legit_node(state):
    return {
        "answer": "Transfer approved",
        "amount": 5000,
        "currency": "USD",
        "recipient": "vendor-alpha",
    }


def banner(title: str):
    width = 42
    print()
    print(BOLD + CYAN + "=" * width + RESET)
    print(BOLD + CYAN + title.center(width) + RESET)
    print(BOLD + CYAN + "=" * width + RESET)
    print()


def pause(msg="..."):
    print(YELLOW + msg + RESET)
    time.sleep(1.8)


def verdict(ok: bool) -> str:
    if ok:
        return GREEN + BOLD + "✅ ACCEPTED" + RESET
    return RED + BOLD + "❌ REJECTED" + RESET


def short_nonce(value: int) -> str:
    return hex(value)[:14] + "..."


def short_hash(value: str) -> str:
    return value[:12] + "..."


def show_output(title, ok, output):
    att = output.get("attestation")
    print(BOLD + title + RESET)
    print("Verification:", verdict(ok))

    result = output["result"]
    for key, value in result.items():
        print(f"{key}: {value}")

    if att is not None:
        print("hash :", short_hash(att.outcome_hash))
        print("nonce:", short_nonce(att.nonce))
    else:
        print("attestation: None")
    print()


def main():
    logging.getLogger("adapters.adapter_langgraph").setLevel(logging.ERROR)

    banner("TRUSTHANDOFF DEMO")

    worker = MockIdentity("agent:worker")
    adapter = TrustHandoffLangGraphAdapter(worker)
    seen_nonces = set()

    pause("Creating signed proof...")
    secured_node = adapter.wrap_node(legit_node)

    clean_output = secured_node({"packet_id": "pk-demo-001"})
    clean_ok = adapter.verify_node_output(
        clean_output,
        worker.public_key_pem,
        seen_nonces=seen_nonces,
    )
    show_output("1) LEGIT", clean_ok, clean_output)

    pause("Attacker tampers with the payload...")

    tampered_output = {
        "result": {
            "answer": "Transfer approved",
            "amount": 5000000,
            "currency": "USD",
            "recipient": "attacker-wallet",
        },
        "attestation": clean_output["attestation"],
    }
    tampered_ok = adapter.verify_node_output(
        tampered_output,
        worker.public_key_pem,
        seen_nonces=set(),  # isolate tampering from replay
    )
    show_output("2) TAMPER", tampered_ok, tampered_output)

    pause("Attacker replays the signed output...")

    replay_ok = adapter.verify_node_output(
        clean_output,
        worker.public_key_pem,
        seen_nonces=seen_nonces,
    )
    show_output("3) REPLAY", replay_ok, clean_output)

    banner("TAKEAWAY")
    print(BOLD + YELLOW + "WITHOUT TrustHandoff:" + RESET)
    print("tampered or replayed")
    print("agent outputs can pass")
    print()

    print(BOLD + CYAN + "WITH TrustHandoff:" + RESET)
    print("signed execution proof")
    print("breaks on tampering")
    print("breaks on replay")
    print()

    print(GREEN + "Legit output verifies once." + RESET)
    print(RED + "Tampered output is rejected." + RESET)
    print(RED + "Replay is rejected." + RESET)
    print()


if __name__ == "__main__":
    main()
