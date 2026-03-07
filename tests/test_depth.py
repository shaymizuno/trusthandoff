from trusthandoff import DelegationChain, within_max_depth


def test_within_max_depth_returns_true_when_depth_is_allowed():
    chain = DelegationChain(
        packet_ids=["pk_001", "pk_002", "pk_003"],
        agents=["agent:a", "agent:b", "agent:c"],
    )

    assert within_max_depth(chain, 3) is True


def test_within_max_depth_returns_false_when_depth_exceeds_limit():
    chain = DelegationChain(
        packet_ids=["pk_001", "pk_002", "pk_003", "pk_004"],
        agents=["agent:a", "agent:b", "agent:c", "agent:d"],
    )

    assert within_max_depth(chain, 3) is False
