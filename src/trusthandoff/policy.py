from trusthandoff.packet import SignedTaskPacket


def check_permission_narrowing(parent: SignedTaskPacket, child: SignedTaskPacket) -> bool:
    """
    Ensure that delegated permissions do not expand authority.

    Child permissions must be a subset of parent permissions.
    """

    parent_actions = set(parent.permissions.allowed_actions)
    child_actions = set(child.permissions.allowed_actions)

    return child_actions.issubset(parent_actions)
