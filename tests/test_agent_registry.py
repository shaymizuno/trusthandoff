from trusthandoff import AgentRegistry


def test_agent_registry_register_and_resolve():
    registry = AgentRegistry()

    registry.register("agent:planner:alpha", "public-key-123")

    assert registry.is_registered("agent:planner:alpha") is True
    assert registry.resolve("agent:planner:alpha") == "public-key-123"


def test_agent_registry_returns_none_for_unknown_agent():
    registry = AgentRegistry()

    assert registry.is_registered("agent:unknown") is False
    assert registry.resolve("agent:unknown") is None
