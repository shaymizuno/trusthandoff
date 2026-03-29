from typing import List, Dict, Any, Optional

from .events import get_events, load_events_from_jsonl


class Sentinel:
    """
    Minimal event-driven auditor.
    Can ingest either in-memory protocol events or external JSONL event logs.
    """

    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    def ingest(self) -> None:
        self.events = get_events()

    def ingest_jsonl(self, path: str) -> None:
        self.events = load_events_from_jsonl(path)

    def detect_violations(self) -> List[Dict[str, Any]]:
        violations = []

        for e in self.events:
            if e["event_type"] == "packet_rejected":
                violations.append(
                    {
                        "type": "rejected_packet",
                        "packet_id": e.get("packet_id"),
                        "reason": e.get("reason"),
                    }
                )

            if e["event_type"] == "capability_stale":
                violations.append(
                    {
                        "type": "stale_capability",
                        "capability_id": e.get("capability_id"),
                        "reason": e.get("reason"),
                    }
                )

            if e["event_type"] == "token_overlap_used":
                violations.append(
                    {
                        "type": "overlap_window_used",
                        "packet_id": e.get("packet_id"),
                        "reason": e.get("reason"),
                    }
                )

            if e["event_type"] == "ai_generated_payload":
                violations.append(
                    {
                        "type": "ai_generated_payload",
                        "packet_id": e.get("packet_id"),
                        "source": e.get("source"),
                        "model": e.get("model"),
                    }
                )

        return violations

    def report(self) -> None:
        violations = self.detect_violations()

        if not violations:
            print("No violations detected")
            return

        print("=== SENTINEL REPORT ===")
        for v in violations:
            print(v)
