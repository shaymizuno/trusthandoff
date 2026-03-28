from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Callable, Any

DEFAULT_POLICY = {
    "write": 120,  # 2 minutes
    "read": 900,   # 15 minutes
}


def resolve_task_metadata(task: Optional[Callable[..., Any]] = None) -> dict:
    """Resolve TTL/risk metadata from a decorated task or fallback policy."""
    risk_level = "read"
    ttl_seconds = DEFAULT_POLICY["read"]

    if task is not None and hasattr(task, "_trusthandoff_metadata"):
        meta = getattr(task, "_trusthandoff_metadata") or {}
        risk_level = meta.get("risk_level", "read")
        ttl_seconds = meta.get("ttl_seconds", DEFAULT_POLICY.get(risk_level, 900))
    else:
        ttl_seconds = DEFAULT_POLICY.get(risk_level, 900)

    return {
        "risk_level": risk_level,
        "ttl_seconds": ttl_seconds,
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


def signed_task(ttl_seconds: Optional[int] = None, risk_level: str = "read"):
    """Attach risk level and TTL to a task (annotation only)."""
    if risk_level not in DEFAULT_POLICY:
        risk_level = "read"

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        wrapper._trusthandoff_metadata = {
            "ttl_seconds": ttl_seconds or DEFAULT_POLICY[risk_level],
            "risk_level": risk_level,
        }
        return wrapper

    return decorator
