from typing import Any, Callable

from .decision import PacketDecision
from .packet import SignedTaskPacket
from .validation import validate_packet
from .verification import verify_packet


AuditCollector = Callable[[dict[str, Any]], None]


def _emit_audit(
    audit_collector: AuditCollector | None,
    event: str,
    packet: SignedTaskPacket,
    details: dict[str, Any] | None = None,
) -> None:
    if audit_collector is None:
        return

    payload: dict[str, Any] = {
        "event": event,
        "packet_id": packet.packet_id,
        "task_id": packet.task_id,
        "from_agent": packet.from_agent,
        "to_agent": packet.to_agent,
        "intent": packet.intent,
    }

    if details:
        payload["details"] = details

    try:
        audit_collector(payload)
    except Exception:
        # Audit must never break the trust decision path.
        pass


def process_handoff(
    packet: SignedTaskPacket,
    audit_collector: AuditCollector | None = None,
) -> PacketDecision:
    # Signature verification runs before packet validation on purpose:
    # do not spend time validating timestamps for forged packets.
    if not verify_packet(packet):
        _emit_audit(
            audit_collector,
            "handoff_rejected_invalid_signature",
            packet,
            {
                "reason": "Invalid signature",
                "signature_preview": packet.signature[:16] + "...",
            },
        )
        return PacketDecision(
            packet_id=packet.packet_id,
            decision="REJECT",
            reason="Invalid signature",
        )

    validation_result = validate_packet(packet)

    if not validation_result.is_valid:
        _emit_audit(
            audit_collector,
            "handoff_rejected_invalid_packet",
            packet,
            {
                "reason": validation_result.reason,
                "issued_at": packet.issued_at.isoformat(),
                "expires_at": packet.expires_at.isoformat(),
            },
        )
        return PacketDecision(
            packet_id=packet.packet_id,
            decision="REJECT",
            reason=validation_result.reason or "Packet validation failed",
        )

    _emit_audit(
        audit_collector,
        "handoff_accepted",
        packet,
        {
            "reason": "Packet verified and valid",
            "issued_at": packet.issued_at.isoformat(),
            "expires_at": packet.expires_at.isoformat(),
        },
    )
    return PacketDecision(
        packet_id=packet.packet_id,
        decision="ACCEPT",
        reason="Packet verified and valid",
    )
