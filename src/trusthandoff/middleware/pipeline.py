from typing import Callable, List
from trusthandoff.envelope import DelegationEnvelope
from trusthandoff.decision import PacketDecision


VerificationStep = Callable[[DelegationEnvelope], PacketDecision]


class VerificationPipeline:
    """
    Executes a sequence of verification steps.

    Stops immediately if any step returns a REJECT decision.
    """

    def __init__(self, steps: List[VerificationStep]):
        self.steps = steps

    def verify(self, envelope: DelegationEnvelope) -> PacketDecision:
        for step in self.steps:
            decision = step(envelope)

            if decision.decision != "ACCEPT":
                return decision

        return PacketDecision(
            packet_id=envelope.packet.packet_id,
            decision="ACCEPT",
            reason=None,
        )
