from .chain import DelegationChain


def within_max_depth(chain: DelegationChain, max_depth: int) -> bool:
    """
    Returns True if the delegation chain depth is within the allowed maximum.
    """

    return chain.depth() <= max_depth
