from trusthandoff.agent_registry import AgentRegistry


def test_agent_revocation_flag():
    registry = AgentRegistry()

    agent_id = "agent-alpha"
    public_key = "demo-key"

    registry.register(agent_id, public_key)

    assert registry.is_registered(agent_id) is True
    assert registry.is_revoked(agent_id) is False

    registry.revoke(agent_id)

    assert registry.is_revoked(agent_id) is True
