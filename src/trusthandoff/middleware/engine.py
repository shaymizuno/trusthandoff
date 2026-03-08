from trusthandoff.middleware.pipeline import run_verification_pipeline
from trusthandoff.middleware.decision import PacketDecision


class TrustHandoffMiddleware:

    def verify(self, packet) -> PacketDecision:
        return run_verification_pipeline(packet)

    def process(self, packet, execute_callable):

        decision = self.verify(packet)

        if decision.accepted:
            return execute_callable()

        raise Exception(f"Delegation rejected: {decision.reason}")
