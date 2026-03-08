from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    DelegationChain,
    DelegationEnvelope,
    Permissions,
    SignedTaskPacket,
    TrustHandoffExecutor,
    sign_packet,
)


def test_executor_does_not_run_callable_when_packet_is_rejected():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    packet = SignedTaskPacket(
        packet_id="pk_exec_reject_001",
        task_id="task_exec_reject_001",
        from_agent=planner.agent_id,
        to_agent=research.agent_id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-exec-reject-001",
        intent="Rejected delegated task",
        context={"company": "Example Corp"},
        permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        signature_algo="Ed25519",
        signature="",
        public_key=planner.public_key_pem,
    )

    signed_packet = sign_packet(packet, planner)

    # chain deeper than middleware max_depth
    envelope = DelegationEnvelope(
        packet=signed_packet,
        chain=DelegationChain(
            packet_ids=["pk1", "pk2", "pk3", "pk4", "pk5", "pk6"],
            agents=["a", "b", "c", "d", "e", "f"],
        ),
    )

    executor = TrustHandoffExecutor(max_depth=5)

    called = {"value": False}

    def blocked_task():
        called["value"] = True
        return "should not run"

    decision, result = executor.execute(envelope, blocked_task)

    assert decision.decision == "REJECT"
    assert decision.reason == "Delegation depth exceeded"
    assert result is None
    assert called["value"] is False
