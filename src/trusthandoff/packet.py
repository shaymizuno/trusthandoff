from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator

from trusthandoff.decorators import DEFAULT_POLICY


class Permissions(BaseModel):
    allowed_actions: List[str] = Field(default_factory=list)
    max_tool_calls: Optional[int] = None


class Constraints(BaseModel):
    max_runtime_seconds: Optional[int] = None
    data_boundary: Optional[str] = None
    requires_human_review: Optional[bool] = False


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

    # Optional TTL/risk metadata
    risk_level: Optional[str] = None
    ttl_seconds: Optional[int] = None
    ai_provenance: Optional[Dict[str, Any]] = None

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

        self.risk_level = resolved_risk
        self.ttl_seconds = resolved_ttl
        return self


    @classmethod
    def from_task(
        cls,
        *,
        task,
        packet_id: str,
        task_id: str,
        from_agent: str,
        to_agent: str,
        nonce: str,
        intent: str,
        permissions: Permissions,
        signature_algo: str,
        signature: str,
        public_key: str,
        capability_token: Optional[str] = None,
        issued_at: Optional[datetime] = None,
        task_type: Optional[str] = None,
        goal: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        memory_refs: Optional[List[str]] = None,
        constraints: Optional[Constraints] = None,
        provenance: Optional[Provenance] = None,
        ai_provenance: Optional[Dict[str, Any]] = None,
    ) -> "SignedTaskPacket":
        """
        Canonical packet creation rail.

        This is the preferred way to create new packets from decorated tasks.
        It propagates task metadata into the packet so packet-level validation
        can enforce policy consistently.
        """
        issued_at = issued_at or datetime.now(timezone.utc)
        task_meta = getattr(task, "_trusthandoff_metadata", {}) or {}

        return cls(
            packet_id=packet_id,
            task_id=task_id,
            from_agent=from_agent,
            to_agent=to_agent,
            issued_at=issued_at,
            expires_at=None,
            nonce=nonce,
            capability_token=capability_token,
            intent=intent,
            task_type=task_type,
            goal=goal,
            context=context or {},
            memory_refs=memory_refs or [],
            permissions=permissions,
            constraints=constraints,
            provenance=provenance,
            signature_algo=signature_algo,
            signature=signature,
            public_key=public_key,
            risk_level=task_meta.get("risk_level"),
            ttl_seconds=task_meta.get("ttl_seconds"),
            ai_provenance=ai_provenance,
        )

