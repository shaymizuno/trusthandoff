from trusthandoff import DelegationChain


def test_delegation_chain_tracks_handoffs():
    chain = DelegationChain(
        packet_ids=[],
        agents=[]
    )

    chain.add_handoff("pk_001", "agent:planner:alpha")
    chain.add_handoff("pk_002", "agent:research:beta")

    assert chain.depth() == 2
    assert chain.packet_ids == ["pk_001", "pk_002"]
    assert chain.agents == ["agent:planner:alpha", "agent:research:beta"]
