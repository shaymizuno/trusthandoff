from trusthandoff.decision import PacketDecision
from trusthandoff.envelope import DelegationEnvelope


class TrustHandoffExecutor:
    """
    Execution gate for delegated tasks.

    Uses TrustHandoffMiddleware to verify an envelope
    before executing a provided callable.
    """

    def __init__(self, middleware=None, max_depth: int = 5):
        if middleware is None:
            from . import TrustHandoffMiddleware
            middleware = TrustHandoffMiddleware(max_depth=max_depth)
        self.middleware = middleware

    def execute(self, envelope: DelegationEnvelope, task_callable):
        decision = self.middleware.handle(envelope)

        if decision.decision != "ACCEPT":
            return decision, None

        result = task_callable()

        return (
            PacketDecision(
                packet_id=envelope.packet.packet_id,
                decision="ACCEPT",
                reason="Task executed",
            ),
            result,
        )
