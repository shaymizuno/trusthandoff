from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator

from trusthandoff.decorators import DEFAULT_POLICY


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
    expires_at: Optional[datetime] = None
    nonce: str
    capability_token: Optional[str] = None
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

    # New optional policy metadata
    risk_level: Optional[str] = None
    ttl_seconds: Optional[int] = None

    @model_validator(mode="after")
    def apply_ttl_policy(self):
        """
        Central TTL enforcement.

        Rules:
        - If neither risk_level nor ttl_seconds is provided:
          keep old behavior unchanged.
        - If risk_level is provided:
          resolve default TTL from DEFAULT_POLICY unless ttl_seconds overrides it.
        - If expires_at is omitted:
          compute it from issued_at + resolved TTL.
        - If expires_at is provided and mismatches the resolved TTL:
          reject the packet.
        """
        # Backward-compatible: do nothing for old packets
        if self.risk_level is None and self.ttl_seconds is None:
            return self

        resolved_risk = self.risk_level or "read"
        if resolved_risk not in DEFAULT_POLICY:
            raise ValueError(f"Unsupported risk_level: {resolved_risk}")

        resolved_ttl = self.ttl_seconds
        if resolved_ttl is None:
            resolved_ttl = DEFAULT_POLICY[resolved_risk]

        expected_expires_at = self.issued_at + timedelta(seconds=resolved_ttl)

        if self.expires_at is None:
            self.expires_at = expected_expires_at
        elif self.expires_at != expected_expires_at:
            raise ValueError(
                f"expires_at does not match TTL policy "
                f"(risk_level={resolved_risk}, ttl_seconds={resolved_ttl})"
            )

        # Normalize resolved values onto the packet
        self.risk_level = resolved_risk
        self.ttl_seconds = resolved_ttl

        return self
