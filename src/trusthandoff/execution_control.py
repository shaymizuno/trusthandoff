from typing import Any, Callable

from .agent_registry import AgentRegistry
from .authorization import is_action_authorized
from .capability import DelegationCapability
from .revocation import CapabilityRevocationRegistry
from .capability_signing import verify_capability_signature
from .capability_chain_validation import validate_capability_chain
from .revocation_validation import is_chain_revoked
from .capability_token import decode_capability_token
from .packet import SignedTaskPacket
from .capability_extraction import extract_capability_token

def execute_authorized_action(
    capabilities: list[DelegationCapability],
    action: str,
    fn: Callable[[], Any],
    registry: AgentRegistry | None = None,
    revocation_registry: CapabilityRevocationRegistry | None = None,
    tool_calls_used: int = 0,
) -> tuple[bool, Any]:
    """
    Executes a callable only if the capability chain is valid and the action is authorized.
    """

    if not capabilities:
        return False, None

    if not verify_capability_chain_for_execution(
        capabilities,
        registry=registry,
        revocation_registry=revocation_registry,
    ):
        return False, None

    leaf_capability = capabilities[-1]

    if not is_action_authorized(
        leaf_capability,
        action=action,
        tool_calls_used=tool_calls_used,
    ):
        return False, None

    return True, fn()


def execute_packet_authorized_action(
    packet: SignedTaskPacket,
    fn: Callable[[], Any],
    registry: AgentRegistry | None = None,
    revocation_registry: CapabilityRevocationRegistry | None = None,
    tool_calls_used: int = 0,
) -> tuple[bool, Any]:
    """
    Executes a callable only if the packet carries a valid capability token
    and the requested intent is authorized.
    """

    token = extract_capability_token(packet)
    if token is None:
        return False, None

    capability = decode_capability_token(token)

    return execute_authorized_action(
        [capability],
        action=packet.intent,
        fn=fn,
        registry=registry,
        revocation_registry=revocation_registry,
        tool_calls_used=tool_calls_used,
    )

def verify_capability_chain_for_execution(
    capabilities: list[DelegationCapability],
    registry: AgentRegistry | None = None,
    revocation_registry: CapabilityRevocationRegistry | None = None,
) -> bool:
    if revocation_registry is not None:
        if is_chain_revoked(capabilities, revocation_registry):
            return False

    if registry is not None:
        for cap in capabilities:
            if revocation_registry is not None and revocation_registry.is_revoked(cap.capability_id):
                return False

            expected_key = registry.resolve(cap.issuer_agent)
            if expected_key is None:
                return False

            if expected_key != cap.public_key:
                return False

            if not verify_capability_signature(cap):
                return False

    return validate_capability_chain(capabilities)
