from trusthandoff.decision import PacketDecision
from trusthandoff.envelope import DelegationEnvelope
from trusthandoff.handoff import process_handoff
from trusthandoff.middleware.pipeline import VerificationPipeline
from trusthandoff.middleware.steps import replay_check, make_depth_check
from .executor import TrustHandoffExecutor

class TrustHandoffMiddleware:

    def __init__(self, max_depth: int = 5):
        self.max_depth = max_depth
        self.pipeline = VerificationPipeline([
            replay_check,
            make_depth_check(max_depth),
        ])

    def handle(self, envelope: DelegationEnvelope) -> PacketDecision:
        decision = self.pipeline.verify(envelope)

        if decision.decision != "ACCEPT":
            return decision

        return process_handoff(envelope.packet)
