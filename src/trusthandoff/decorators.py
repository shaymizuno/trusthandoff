from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Callable, Any, Dict

DEFAULT_POLICY = {
    "write": 120,  # 2 minutes
    "read": 900,   # 15 minutes
}


def resolve_task_metadata(task: Optional[Callable[..., Any]] = None) -> dict:
    """Resolve metadata from a decorated task or fallback policy."""
    risk_level = "read"
    ttl_seconds = DEFAULT_POLICY["read"]
    requires_human_review = False
    ai_provenance = None

    if task is not None and hasattr(task, "_trusthandoff_metadata"):
        meta = getattr(task, "_trusthandoff_metadata") or {}
        risk_level = meta.get("risk_level", "read")
        ttl_seconds = meta.get("ttl_seconds", DEFAULT_POLICY.get(risk_level, 900))
        requires_human_review = meta.get("requires_human_review", False)
        ai_provenance = meta.get("ai_provenance")

    return {
        "risk_level": risk_level,
        "ttl_seconds": ttl_seconds,
        "requires_human_review": requires_human_review,
        "ai_provenance": ai_provenance,
    }


def compute_expires_at(
    issued_at: Optional[datetime] = None,
    *,
    task: Optional[Callable[..., Any]] = None,
    ttl_seconds: Optional[int] = None,
    risk_level: Optional[str] = None,
) -> datetime:
    """
    Compute expires_at from:
    1. explicit ttl_seconds/risk_level if provided
    2. decorated task metadata if present
    3. DEFAULT_POLICY fallback
    """
    issued_at = issued_at or datetime.now(timezone.utc)

    if ttl_seconds is None:
        if risk_level is not None:
            ttl_seconds = DEFAULT_POLICY.get(risk_level, DEFAULT_POLICY["read"])
        else:
            meta = resolve_task_metadata(task)
            ttl_seconds = meta["ttl_seconds"]

    return issued_at + timedelta(seconds=ttl_seconds)


def signed_task(
    ttl_seconds: Optional[int] = None,
    risk_level: str = "read",
    requires_human_review: bool = False,
    ai_provenance: Optional[Dict[str, Any]] = None,
):
    """Attach policy metadata to a task."""
    if risk_level not in DEFAULT_POLICY:
        risk_level = "read"

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        wrapper._trusthandoff_metadata = {
            "ttl_seconds": ttl_seconds or DEFAULT_POLICY[risk_level],
            "risk_level": risk_level,
            "requires_human_review": requires_human_review,
            "ai_provenance": ai_provenance,
        }
        return wrapper

    return decorator
