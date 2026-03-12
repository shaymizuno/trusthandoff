from datetime import datetime

from .capability import DelegationCapability
from .capability_token import encode_capability_token
from .capability_validation import validate_capability_derivation
from .packet import Permissions
from .capability_signing import sign_capability


def derive_capability_token(
    parent: DelegationCapability,
    child_capability_id: str,
    child_subject_agent: str,
    delegated_permissions: Permissions,
    expires_at: datetime,
    private_key_pem: str,
) -> str:
    """
    Derive a child capability from a parent, sign it, and return a portable token.
    """

    child = DelegationCapability(
        capability_id=child_capability_id,
        issuer_agent=parent.subject_agent,
        subject_agent=child_subject_agent,
        delegated_permissions=delegated_permissions,
        issued_at=datetime.now(parent.issued_at.tzinfo),
        expires_at=expires_at,
        parent_capability_id=parent.capability_id,
        signature_algo=parent.signature_algo,
        signature="",
        public_key=parent.public_key,
    )

    validate_capability_derivation(parent, child)

    signed_child = sign_capability(child, private_key_pem)
    return encode_capability_token(signed_child)
