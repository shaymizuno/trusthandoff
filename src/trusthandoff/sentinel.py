"""
TrustHandoff Sentinel — thin shim over sentinel-core.

Public API is unchanged from v0.3.x except detect_violations() now returns
List[ViolationRecord] instead of List[dict]. This is a 0.4.0 breaking change.

Callers that need the old dict shape:
    [v.model_dump() for v in sentinel.detect_violations()]
"""

from sentinel_core import Sentinel as _CoreSentinel
from sentinel_core.event import ViolationRecord  # re-export for callers

from .events import get_events, load_events_from_jsonl
from .sentinel_adapter import TrustHandoffSentinelAdapter

_ADAPTER = TrustHandoffSentinelAdapter()


class Sentinel(_CoreSentinel):
    """
    TrustHandoff-flavoured Sentinel.

    Adds ingest() and ingest_jsonl() so callers don't have to handle the
    raw-dict → SentinelEvent translation themselves.

    All violation detection and reporting is delegated to sentinel-core.
    """

    def ingest(self) -> None:
        """Ingest events from the trusthandoff in-memory event buffer."""
        self._ingest_raw(get_events())

    def ingest_jsonl(self, path: str) -> None:
        """Ingest events from a JSONL file written by dump_events_to_jsonl()."""
        self._ingest_raw(load_events_from_jsonl(path))

    def _ingest_raw(self, raw_events) -> None:
        super().ingest(_ADAPTER.to_sentinel_event(e) for e in raw_events)


__all__ = ["Sentinel", "ViolationRecord"]
