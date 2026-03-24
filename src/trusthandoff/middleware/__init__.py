from typing import Callable, Optional

from trusthandoff.decision import PacketDecision
from trusthandoff.depth import within_max_depth
from trusthandoff.envelope import DelegationEnvelope
from trusthandoff.handoff import AuditCollector, process_handoff
from trusthandoff.replay import ReplayProtection
from trusthandoff.revalidation import RevalidationWatcher
from .executor import TrustHandoffExecutor


class TrustHandoffMiddleware:
    def __init__(
        self,
        replay_protection: ReplayProtection | None = None,
        max_depth: int = 5,
        revalidate_every_seconds: Optional[float] = None,
    ):
        self.replay_protection = replay_protection or ReplayProtection()
        self.max_depth = max_depth
        self.revalidate_every_seconds = revalidate_every_seconds

    def handle(
        self,
        envelope: DelegationEnvelope,
        audit_collector: AuditCollector | None = None,
    ) -> PacketDecision:
        nonce = envelope.packet.nonce

        if not self.replay_protection.check_and_store(nonce):
            return PacketDecision(
                packet_id=envelope.packet.packet_id,
                decision="REJECT",
                reason="Replay detected",
            )

        if not within_max_depth(envelope.chain, self.max_depth):
            return PacketDecision(
                packet_id=envelope.packet.packet_id,
                decision="REJECT",
                reason="Delegation depth exceeded",
            )

        return process_handoff(
            envelope.packet,
            audit_collector=audit_collector,
        )

    def handle_with_revalidation(
        self,
        envelope: DelegationEnvelope,
        revalidate_fn: Callable[[], bool],
        audit_collector: AuditCollector | None = None,
    ) -> tuple[PacketDecision, RevalidationWatcher | None]:
        decision = self.handle(envelope, audit_collector=audit_collector)

        if decision.decision != "ACCEPT":
            return decision, None

        if self.revalidate_every_seconds is None or self.revalidate_every_seconds <= 0:
            return decision, None

        if revalidate_fn is None:
            raise ValueError("revalidate_fn must be provided when revalidation is enabled")

        watcher = RevalidationWatcher(
            revalidate_fn=revalidate_fn,
            capability_id=envelope.packet.packet_id,
            revalidate_every_seconds=self.revalidate_every_seconds,
        )
        watcher.start()

        return decision, watcher

