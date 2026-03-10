from datetime import datetime
from typing import Optional
from pydantic import BaseModel

from .packet import Permissions, Constraints


class DelegationCapability(BaseModel):
    capability_id: str
    issuer_agent: str
    subject_agent: str

    delegated_permissions: Permissions
    constraints: Optional[Constraints] = None

    issued_at: datetime
    expires_at: datetime

    parent_capability_id: Optional[str] = None

    signature_algo: str
    signature: str
    public_key: str
