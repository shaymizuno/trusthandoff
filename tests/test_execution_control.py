from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    AgentRegistry,
    DelegationCapability,
    encode_capability_token,
    execute_authorized_action,
    execute_packet_authorized_action,
    sign_capability,
)
from trusthandoff.packet import Permissions, SignedTaskPacket


def test_execute_authorized_action_runs_callable_when_authorized():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    registry = AgentRegistry()
    registry.register(planner.agent_id, planner.public_key_pem)
    registry.register(research.agent_id, research.public_key_pem)

    cap = DelegationCapability(
        capability_id="cap-exec-1",
        issuer_agent=planner.agent_id,
        subject_agent=research.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="",
        public_key=planner.public_key_pem,
    )
    cap = sign_capability(cap, planner.private_key_pem)

    ok, result = execute_authorized_action(
        [cap],
        action="search",
        fn=lambda: "executed",
        registry=registry,
        tool_calls_used=0,
    )

    assert ok is True
    assert result == "executed"


def test_execute_authorized_action_rejects_disallowed_action():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    registry = AgentRegistry()
    registry.register(planner.agent_id, planner.public_key_pem)
    registry.register(research.agent_id, research.public_key_pem)

    cap = DelegationCapability(
        capability_id="cap-exec-2",
        issuer_agent=planner.agent_id,
        subject_agent=research.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["read"],
            max_tool_calls=2,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="",
        public_key=planner.public_key_pem,
    )
    cap = sign_capability(cap, planner.private_key_pem)

    ok, result = execute_authorized_action(
        [cap],
        action="write",
        fn=lambda: "should not run",
        registry=registry,
        tool_calls_used=0,
    )

    assert ok is False
    assert result is None


def test_execute_packet_authorized_action_runs_callable_when_packet_token_is_valid():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    registry = AgentRegistry()
    registry.register(planner.agent_id, planner.public_key_pem)
    registry.register(research.agent_id, research.public_key_pem)

    cap = DelegationCapability(
        capability_id="cap-pkt-exec-1",
        issuer_agent=planner.agent_id,
        subject_agent=research.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="",
        public_key=planner.public_key_pem,
    )
    cap = sign_capability(cap, planner.private_key_pem)
    token = encode_capability_token(cap)

    packet = SignedTaskPacket(
        packet_id="pkt-exec-1",
        task_id="task-exec-1",
        from_agent=planner.agent_id,
        to_agent=research.agent_id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        nonce="nonce-pkt-exec-1",
        capability_token=token,
        intent="search",
        permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key=planner.public_key_pem,
    )

    ok, result = execute_packet_authorized_action(
        packet,
        fn=lambda: "packet-executed",
        registry=registry,
        tool_calls_used=0,
    )

    assert ok is True
    assert result == "packet-executed"


def test_execute_packet_authorized_action_rejects_missing_capability_token():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    registry = AgentRegistry()
    registry.register(planner.agent_id, planner.public_key_pem)
    registry.register(research.agent_id, research.public_key_pem)

    packet = SignedTaskPacket(
        packet_id="pkt-exec-missing",
        task_id="task-exec-missing",
        from_agent=planner.agent_id,
        to_agent=research.agent_id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        nonce="nonce-pkt-missing",
        capability_token=None,
        intent="search",
        permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key=planner.public_key_pem,
    )

    ok, result = execute_packet_authorized_action(
        packet,
        fn=lambda: "should-not-run",
        registry=registry,
        tool_calls_used=0,
    )

    assert ok is False
    assert result is None
