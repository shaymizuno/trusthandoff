from .agent_registry import AgentRegistry
from .decision import PacketDecision
from .envelope import DelegationEnvelope
from .middleware import TrustHandoffMiddleware


def verify_envelope(
    envelope: DelegationEnvelope,
    max_depth: int = 5,
    registry: AgentRegistry | None = None,
) -> PacketDecision:
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

    middleware = TrustHandoffMiddleware(max_depth=max_depth)
    return middleware.handle(envelope)
