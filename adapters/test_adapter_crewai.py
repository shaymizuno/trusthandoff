from trusthandoff import AgentIdentity
from adapters.adapter_crewai import process_framework_handoff


def main():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    result = process_framework_handoff(
        from_identity=planner,
        to_agent_id=research.agent_id,
        intent="Research company background",
        context={"company": "Example Corp"},
    )

    print("=== CrewAI Adapter Demo ===")
    print("Decision:", result["decision"].decision)
    print("Reason:", result["decision"].reason)
    print("Packet ID:", result["packet"].packet_id)
    print("Chain depth:", result["envelope"].chain.depth())
    print("Chain agents:", result["envelope"].chain.agents)


if __name__ == "__main__":
    main()
