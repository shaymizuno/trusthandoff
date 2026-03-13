from .agent_registry import AgentRegistry
from .decision import PacketDecision
from .envelope import DelegationEnvelope
from .middleware import TrustHandoffMiddleware
from .capability import DelegationCapability
from .capability_chain_validation import validate_capability_chain
from .capability_signing import verify_capability_signature
from .revocation import CapabilityRevocationRegistry
from .revocation_validation import is_chain_revoked
from .execution_control import (execute_authorized_action,execute_packet_authorized_action,)
from .replay_guard import ReplayGuard

replay_guard = ReplayGuard()

def verify_envelope(
    envelope: DelegationEnvelope,
    max_depth: int = 5,
    registry: AgentRegistry | None = None,
) -> PacketDecision:
    if registry is not None and registry.is_revoked(envelope.packet.from_agent):
        return PacketDecision(
            packet_id=envelope.packet.packet_id,
            decision="REJECT",
            reason="agent_revoked",
        )

    if registry is not None:
        expected_key = registry.resolve(envelope.packet.from_agent)

        if expected_key is None:
            return PacketDecision(
                packet_id=envelope.packet.packet_id,
                decision="REJECT",
                reason="Unknown agent identity",
            )

        if expected_key != envelope.packet.public_key:
            return PacketDecision(
                packet_id=envelope.packet.packet_id,
                decision="REJECT",
                reason="Agent identity binding failed",
            )

        if replay_guard.seen(envelope.packet.from_agent, envelope.packet.nonce):
            return PacketDecision(
                packet_id=envelope.packet.packet_id,
                decision="REJECT",
                reason="replay_detected",
            )

    middleware = TrustHandoffMiddleware(max_depth=max_depth)
    return middleware.handle(envelope)


def verify_capability_chain(
    capabilities: list[DelegationCapability],
    registry: AgentRegistry | None = None,
    revocation_registry=None,
) -> bool:

    if revocation_registry is not None:
        if is_chain_revoked(capabilities, revocation_registry):
            return False

    if registry is not None:
        for cap in capabilities:

            if revocation_registry is not None:
                if revocation_registry.is_revoked(cap.capability_id):
                    return False

            expected_key = registry.resolve(cap.issuer_agent)

            if expected_key is None:
                return False

            if expected_key != cap.public_key:
                return False

            if not verify_capability_signature(cap):
                return False

    return validate_capability_chain(capabilities)
