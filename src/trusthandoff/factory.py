from datetime import datetime, timezone
from typing import Optional, Callable, Any

from trusthandoff.packet import SignedTaskPacket
from trusthandoff.decorators import compute_expires_at


def create_signed_task_packet(
    *,
    packet_id: str,
    task_id: str,
    from_agent: str,
    to_agent: str,
    nonce: str,
    intent: str,
    permissions,
    signature_algo: str,
    signature: str,
    public_key: str,
    capability_token,
    task: Optional[Callable[..., Any]] = None,
    ttl_seconds: Optional[int] = None,
    risk_level: Optional[str] = None,
):
    """
    Central factory enforcing TTL policy.
    All new packets should be created via this function.
    """

    issued_at = datetime.now(timezone.utc)

    expires_at = compute_expires_at(
        issued_at,
        task=task,
        ttl_seconds=ttl_seconds,
        risk_level=risk_level,
    )

    return SignedTaskPacket(
        packet_id=packet_id,
        task_id=task_id,
        from_agent=from_agent,
        to_agent=to_agent,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        capability_token=capability_token,
        intent=intent,
        permissions=permissions,
        signature_algo=signature_algo,
        signature=signature,
        public_key=public_key,
    )
