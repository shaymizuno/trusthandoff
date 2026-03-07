from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Permissions(BaseModel):
    allowed_actions: List[str] = Field(default_factory=list)
    max_tool_calls: Optional[int] = None


class Constraints(BaseModel):
    max_runtime_seconds: Optional[int] = None
    data_boundary: Optional[str] = None


class Provenance(BaseModel):
    origin_workflow: Optional[str] = None
    delegation_depth: Optional[int] = None


class SignedTaskPacket(BaseModel):
    packet_id: str
    task_id: str
    from_agent: str
    to_agent: str

    issued_at: datetime
    expires_at: datetime
    nonce: str

    intent: str
    task_type: Optional[str] = None
    goal: Optional[str] = None

    context: Dict[str, Any] = Field(default_factory=dict)
    memory_refs: List[str] = Field(default_factory=list)

    permissions: Permissions
    constraints: Optional[Constraints] = None
    provenance: Optional[Provenance] = None

    signature_algo: str
    signature: str
    public_key: str
