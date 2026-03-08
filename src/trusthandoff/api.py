from .decision import PacketDecision
from .envelope import DelegationEnvelope
from .middleware import TrustHandoffMiddleware


def verify_envelope(envelope: DelegationEnvelope, max_depth: int = 5) -> PacketDecision:
    middleware = TrustHandoffMiddleware(max_depth=max_depth)
    return middleware.handle(envelope)
