from .capability import DelegationCapability


def is_action_authorized(
    capability: DelegationCapability,
    action: str,
    tool_calls_used: int = 0,
) -> bool:
    """
    Returns True if the requested action is authorized by the capability.
    """

    allowed = capability.delegated_permissions.allowed_actions

    if action not in allowed:
        return False

    max_tool_calls = capability.delegated_permissions.max_tool_calls

    if max_tool_calls is not None and tool_calls_used >= max_tool_calls:
        return False

    return True
