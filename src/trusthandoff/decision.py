from typing import Literal, Optional, Dict, Any
from pydantic import BaseModel, field_validator, ConfigDict

from .attestation import ExecutionAttestation


DecisionType = Literal["ACCEPT", "REJECT"]

MAX_REASON_LENGTH = 256
MAX_STRING_LENGTH = 256
MAX_KEY_LENGTH = 128
MAX_CONTAINER_ITEMS = 20
MAX_SANITIZE_DEPTH = 4
MAX_BYTES_PREVIEW = 32


def _sanitize_key(key: Any) -> str:
    text = str(key)
    if len(text) > MAX_KEY_LENGTH:
        return text[:MAX_KEY_LENGTH] + "..."
    return text


def _sanitize_value(value: Any, depth: int = 0) -> Any:
    if depth >= MAX_SANITIZE_DEPTH:
        return "<max_depth_reached>"

    if value is None or isinstance(value, (int, float, bool)):
        return value

    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            return value[:MAX_STRING_LENGTH] + "..."
        return value

    if isinstance(value, bytes):
        preview = value[:MAX_BYTES_PREVIEW].hex()
        if len(preview) > 64:
            preview = preview[:64]
        return f"<bytes:{preview}...>"

    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            if count >= MAX_CONTAINER_ITEMS:
                sanitized["<truncated>"] = True
                break
            sanitized[_sanitize_key(key)] = _sanitize_value(item, depth + 1)
            count += 1
        return sanitized

    if isinstance(value, (list, tuple, set)):
        sanitized_list = []
        for idx, item in enumerate(value):
            if idx >= MAX_CONTAINER_ITEMS:
                sanitized_list.append("<truncated>")
                break
            sanitized_list.append(_sanitize_value(item, depth + 1))
        return sanitized_list

    return f"<unsupported:{type(value).__name__}>"


def _sanitize_details(value: Dict[str, Any]) -> Dict[str, Any]:
    result = _sanitize_value(value, depth=0)
    assert isinstance(result, dict)
    return result


class PacketDecision(BaseModel):
    packet_id: str
    decision: DecisionType
    reason: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    execution_attestation: Optional[ExecutionAttestation] = None

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    @field_validator("reason")
    @classmethod
    def validate_reason_length(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if len(value) > MAX_REASON_LENGTH:
            raise ValueError("reason too long")
        return value

    @field_validator("details")
    @classmethod
    def sanitize_details(cls, value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if value is None:
            return value
        return _sanitize_details(value)
