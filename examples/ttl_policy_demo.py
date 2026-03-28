from datetime import datetime, timezone, timedelta

from trusthandoff.packet import SignedTaskPacket, Permissions

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def verdict(ok: bool) -> str:
    return GREEN + "✅" + RESET if ok else RED + "❌" + RESET


def main():
    print("=== TRUSTHANDOFF × TTL POLICY DEMO ===")

    issued = datetime.now(timezone.utc)

    write_packet = SignedTaskPacket(
        packet_id="write-1",
        task_id="task-write",
        from_agent="agent:a",
        to_agent="agent:b",
        issued_at=issued,
        expires_at=issued + timedelta(seconds=120),
        nonce="nonce-write",
        intent="mutate_record",
        permissions=Permissions(),
        signature_algo="Ed25519",
        signature="sig",
        public_key="pk",
        risk_level="write",
    )

    write_ttl = int((write_packet.expires_at - write_packet.issued_at).total_seconds())
    print(f"WRITE task TTL: {write_ttl}s", verdict(write_ttl == 120))

    read_packet = SignedTaskPacket(
        packet_id="read-1",
        task_id="task-read",
        from_agent="agent:a",
        to_agent="agent:b",
        issued_at=issued,
        expires_at=issued + timedelta(seconds=900),
        nonce="nonce-read",
        intent="read_record",
        permissions=Permissions(),
        signature_algo="Ed25519",
        signature="sig",
        public_key="pk",
        risk_level="read",
    )

    read_ttl = int((read_packet.expires_at - read_packet.issued_at).total_seconds())
    print(f"READ task TTL:  {read_ttl}s", verdict(read_ttl == 900))

    print("\n--- ATTACK: mismatched TTL on write ---")
    try:
        SignedTaskPacket(
            packet_id="write-bad",
            task_id="task-write-bad",
            from_agent="agent:a",
            to_agent="agent:b",
            issued_at=issued,
            expires_at=issued + timedelta(seconds=999),
            nonce="nonce-bad",
            intent="mutate_record",
            permissions=Permissions(),
            signature_algo="Ed25519",
            signature="sig",
            public_key="pk",
            risk_level="write",
        )
        print("Mismatch accepted", verdict(False))
    except ValueError:
        print("Mismatch rejected", verdict(True))


if __name__ == "__main__":
    main()
