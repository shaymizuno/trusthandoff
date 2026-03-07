from trusthandoff import AgentIdentity
from adapters.adapter_autogen import process_framework_handoff


def main():
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()

    result = process_framework_handoff(
        source_identity=source,
        target_agent_id=target.agent_id,
        handoff_intent="Delegate analysis task",
        context={"company": "Example Corp", "task": "analysis"},
    )

    print("=== AutoGen Adapter Demo ===")
    print("Decision:", result["decision"].decision)
    print("Reason:", result["decision"].reason)
    print("Packet ID:", result["packet"].packet_id)
    print("Chain depth:", result["envelope"].chain.depth())
    print("Chain agents:", result["envelope"].chain.agents)


if __name__ == "__main__":
    main()
