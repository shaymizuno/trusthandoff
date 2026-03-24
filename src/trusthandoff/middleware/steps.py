from trusthandoff.envelope import DelegationEnvelope
from trusthandoff.decision import PacketDecision
from trusthandoff.replay import ReplayProtection
from trusthandoff.depth import within_max_depth
from trusthandoff.replay import ReplayProtection

replay_store = ReplayProtection()

def reset_replay_store():
    global replay_store
    replay_store = ReplayProtection()

def replay_check(envelope: DelegationEnvelope) -> PacketDecision:
    packet = envelope.packet

    if not replay_store.check_and_store(packet.nonce):
        return PacketDecision(
            packet_id=packet.packet_id,
            decision="REJECT",
            reason="Replay detected",
        )

    return PacketDecision(
        packet_id=packet.packet_id,
        decision="ACCEPT",
        reason=None,
    )


def make_depth_check(max_depth: int):
    def depth_check(envelope: DelegationEnvelope) -> PacketDecision:
        packet = envelope.packet

        if not within_max_depth(envelope.chain, max_depth):
            return PacketDecision(
                packet_id=packet.packet_id,
                decision="REJECT",
                reason="Delegation depth exceeded",
            )

        return PacketDecision(
            packet_id=packet.packet_id,
            decision="ACCEPT",
            reason=None,
        )

    return depth_check
