from datetime import datetime, timezone, timedelta

from trusthandoff.packet import SignedTaskPacket, Permissions, Constraints
from trusthandoff.validation import validate_packet

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def verdict(ok: bool) -> str:
    return GREEN + "✅" + RESET if ok else RED + "❌" + RESET


def main():
    print("=== TRUSTHANDOFF × HUMAN REVIEW DEMO ===")

    issued = datetime.now(timezone.utc)

    # Case 1 — requires human review but no approval
    packet_blocked = SignedTaskPacket(
        packet_id="p1",
        task_id="t1",
        from_agent="agent:a",
        to_agent="agent:b",
        issued_at=issued,
        expires_at=issued + timedelta(minutes=5),
        nonce="n1",
        intent="deploy_change",
        permissions=Permissions(),
        constraints=Constraints(requires_human_review=True),
        signature_algo="algo",
        signature="sig",
        public_key="pk",
    )

    result_blocked = validate_packet(packet_blocked)
    print("Blocked without approval:", verdict(not result_blocked.is_valid))

    # Case 2 — requires human review with approval
    packet_approved = SignedTaskPacket(
        packet_id="p2",
        task_id="t2",
        from_agent="agent:a",
        to_agent="agent:b",
        issued_at=issued,
        expires_at=issued + timedelta(minutes=5),
        nonce="n2",
        intent="deploy_change",
        permissions=Permissions(),
        constraints=Constraints(requires_human_review=True),
        context={"human_approval": "signed_by_senior"},
        signature_algo="algo",
        signature="sig",
        public_key="pk",
    )

    result_approved = validate_packet(packet_approved)
    print("Allowed with approval:", verdict(result_approved.is_valid))

    print("\nTAKEAWAY")
    print("- critical actions can be blocked at protocol level")
    print("- execution requires explicit human approval")


if __name__ == "__main__":
    main()
