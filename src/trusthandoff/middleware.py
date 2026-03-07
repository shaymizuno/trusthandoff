from .decision import PacketDecision
from .envelope import DelegationEnvelope
from .handoff import process_handoff


class TrustHandoffMiddleware:
    """
    Minimal middleware entrypoint for TrustHandoff.
    """

    def handle(self, envelope: DelegationEnvelope) -> PacketDecision:
        return process_handoff(envelope.packet)
