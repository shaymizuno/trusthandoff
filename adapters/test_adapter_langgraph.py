from trusthandoff import AgentIdentity
from adapters.adapter_langgraph import process_framework_handoff


def main():
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()

    result = process_framework_handoff(
        source_identity=source,
        target_agent_id=target.agent_id,
        state_intent="Route research task to specialist agent",
        state_context={"company": "Example Corp", "graph_state": "research_needed"},
    )

    print("=== LangGraph Adapter Demo ===")
    print("Decision:", result["decision"].decision)
    print("Reason:", result["decision"].reason)
    print("Packet ID:", result["packet"].packet_id)
    print("Chain depth:", result["envelope"].chain.depth())
    print("Chain agents:", result["envelope"].chain.agents)


if __name__ == "__main__":
    main()
