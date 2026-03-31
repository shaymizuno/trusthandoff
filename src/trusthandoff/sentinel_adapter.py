"""
TrustHandoff → sentinel-core adapter.

Translates raw trusthandoff event dicts (produced by trusthandoff.events)
into the universal SentinelEvent schema.

This is the only file in TrustHandoff that knows about SentinelEvent internals.
"""

from datetime import datetime, timezone
from typing import Any, Dict

from sentinel_core.event import SentinelEvent


_SEVERITY_MAP: Dict[str, str] = {
    "packet_accepted": "INFO",
    "packet_rejected": "ERROR",
    "capability_stale": "ERROR",
    "token_overlap_used": "WARN",
    "ai_generated_payload": "WARN",
}

# Fields promoted to top-level SentinelEvent fields; everything else goes
# into `attributes` so no domain detail is lost.
_TOP_LEVEL_KEYS = {
    "event_id",
    "event_type",
    "timestamp",
    "producer_id",
    "correlation_id",
    "idempotency_key",
}


class TrustHandoffSentinelAdapter:
    source_system = "trusthandoff"

    def to_sentinel_event(self, raw: Dict[str, Any]) -> SentinelEvent:
        event_type = raw.get("event_type", "unknown")
        timestamp_raw = raw.get("timestamp")
        if isinstance(timestamp_raw, str):
            timestamp = datetime.fromisoformat(timestamp_raw)
        elif isinstance(timestamp_raw, datetime):
            timestamp = timestamp_raw
        else:
            timestamp = datetime.now(timezone.utc)

        # Ensure timezone-aware
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        attributes = {k: v for k, v in raw.items() if k not in _TOP_LEVEL_KEYS}

        body_parts = [event_type]
        reason = raw.get("reason") or attributes.get("reason")
        if reason:
            body_parts.append(str(reason))

        return SentinelEvent(
            event_id=raw.get("event_id", ""),
            event_type=event_type,
            timestamp=timestamp,
            observed_at=datetime.now(timezone.utc),
            severity=_SEVERITY_MAP.get(event_type, "INFO"),
            producer_id=raw.get("producer_id"),
            trace_id=raw.get("correlation_id"),
            span_id=None,
            body=" — ".join(body_parts),
            attributes=attributes,
            source_system=self.source_system,
        )
