from datetime import datetime

from .capability import DelegationCapability
from .capability_propagation import derive_capability_token
from .packet import Permissions, SignedTaskPacket


def derive_packet_with_capability(
    parent_capability: DelegationCapability,
    child_capability_id: str,
    child_subject_agent: str,
    delegated_permissions: Permissions,
    capability_expires_at: datetime,
    private_key_pem: str,
    packet_id: str,
    task_id: str,
    from_agent: str,
    to_agent: str,
    issued_at: datetime,
    expires_at: datetime,
    nonce: str,
    intent: str,
    permissions: Permissions,
    signature_algo: str,
    signature: str,
    public_key: str,
) -> SignedTaskPacket:
    """
    Derive a child capability token and embed it into a new SignedTaskPacket.
    """

    token = derive_capability_token(
        parent=parent_capability,
        child_capability_id=child_capability_id,
        child_subject_agent=child_subject_agent,
        delegated_permissions=delegated_permissions,
        expires_at=capability_expires_at,
        private_key_pem=private_key_pem,
    )

    return SignedTaskPacket(
        packet_id=packet_id,
        task_id=task_id,
        from_agent=from_agent,
        to_agent=to_agent,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        capability_token=token,
        intent=intent,
        permissions=permissions,
        signature_algo=signature_algo,
        signature=signature,
        public_key=public_key,
    )
