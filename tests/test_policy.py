from datetime import datetime, timedelta, timezone

from trusthandoff import (
    Permissions,
    SignedTaskPacket,
    check_permission_narrowing,
)


def make_packet(actions):
    return SignedTaskPacket(
        packet_id="pk_policy",
        task_id="task_policy",
        from_agent="agent:a",
        to_agent="agent:b",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce",
        intent="policy test",
        context={},
        permissions=Permissions(
            allowed_actions=actions,
            max_tool_calls=5
        ),
        signature_algo="Ed25519",
        signature="sig",
        public_key="pk",
    )


def test_permission_narrowing_accepts_subset():
    parent = make_packet(["read", "search", "summarize"])
    child = make_packet(["read", "search"])

    assert check_permission_narrowing(parent, child)


def test_permission_narrowing_rejects_expansion():
    parent = make_packet(["read"])
    child = make_packet(["read", "write"])

    assert not check_permission_narrowing(parent, child)
