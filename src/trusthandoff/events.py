import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


_EVENT_BUFFER: List[Dict[str, Any]] = []
_LOCK = threading.Lock()

# Optional external sink: callable(event_dict) -> None
_EVENT_SINK: Optional[Callable[[Dict[str, Any]], None]] = None


def set_event_sink(fn: Optional[Callable[[Dict[str, Any]], None]]) -> None:
    """
    Register an optional external event sink.

    Example future use cases:
    - send to Kafka
    - send to HTTP webhook
    - send to Redis stream
    - send to OpenTelemetry bridge
    """
    global _EVENT_SINK
    _EVENT_SINK = fn


class KafkaEventSink:
    """
    Kafka producer sink with partitioned ordering.

    Guarantees:
    - strict ordering per correlation_id (Kafka partition key)
    - at-least-once delivery (idempotency handled upstream)
    """

    def __init__(self, bootstrap_servers: str, topic: str):
        try:
            from kafka import KafkaProducer
        except ImportError as exc:
            raise ImportError(
                "KafkaEventSink requires the 'kafka-python' package. "
                "Install it with: pip install kafka-python"
            ) from exc

        self.topic = topic
        self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers.split(","),
            acks="all",  # strongest durability
            retries=5,
            key_serializer=lambda k: k.encode("utf-8"),
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )

    def __call__(self, event: Dict[str, Any]) -> None:
        key = (
            event.get("correlation_id")
            or event.get("packet_id")
            or event.get("capability_id")
            or "default"
        )

        self.producer.send(self.topic, key=key, value=event)

def emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    correlation_id = (
        payload.get("correlation_id")
        or payload.get("packet_id")
        or payload.get("capability_id")
    )

    producer_id = (
        payload.get("producer_id")
        or payload.get("from_agent")
        or payload.get("issuer_agent")
        or "unknown"
    )

    idempotency_key = (
        payload.get("idempotency_key")
        or correlation_id
        or str(uuid.uuid4())
    )

    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "producer_id": producer_id,
        "correlation_id": correlation_id,
        "idempotency_key": idempotency_key,
        **payload,
    }

    with _LOCK:
        _EVENT_BUFFER.append(event)

    if _EVENT_SINK is not None:
        _EVENT_SINK(event)


def get_events() -> List[Dict[str, Any]]:
    with _LOCK:
        return list(_EVENT_BUFFER)


def clear_events() -> None:
    with _LOCK:
        _EVENT_BUFFER.clear()


def dump_events_to_jsonl(path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for event in get_events():
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def load_events_from_jsonl(path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
    return events
