from .capability import DelegationCapability


def validate_capability_derivation(parent: DelegationCapability, child: DelegationCapability) -> bool:
    """
    Ensures that a derived capability does not expand authority relative to its parent.
    """

    # issuer of child must be the subject of parent
    if parent.subject_agent != child.issuer_agent:
        return False

    # child must reference parent
    if child.parent_capability_id != parent.capability_id:
        return False

    # expiration must not exceed parent
    if child.expires_at > parent.expires_at:
        return False

    # permissions must be subset
    parent_actions = set(parent.delegated_permissions.allowed_actions)
    child_actions = set(child.delegated_permissions.allowed_actions)

    if not child_actions.issubset(parent_actions):
        return False

    # tool call limits must not increase
    parent_tools = parent.delegated_permissions.max_tool_calls
    child_tools = child.delegated_permissions.max_tool_calls

    if parent_tools is not None and child_tools is not None:
        if child_tools > parent_tools:
            return False

    return True
