from .decision import PacketDecision
from .envelope import DelegationEnvelope
from .handoff import process_handoff
from .replay import ReplayProtection


class TrustHandoffMiddleware:
    """
    Minimal middleware entrypoint for TrustHandoff.
    """

    def __init__(self, replay_protection: ReplayProtection | None = None):
        self.replay_protection = replay_protection or ReplayProtection()

    def handle(self, envelope: DelegationEnvelope) -> PacketDecision:
        nonce = envelope.packet.nonce

        if not self.replay_protection.check_and_store(nonce):
            return PacketDecision(
                packet_id=envelope.packet.packet_id,
                decision="REJECT",
                reason="Replay detected",
            )

        return process_handoff(envelope.packet)
