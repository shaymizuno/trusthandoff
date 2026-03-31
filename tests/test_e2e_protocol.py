import time
from datetime import datetime, timezone, timedelta

from trusthandoff.packet import SignedTaskPacket, Permissions
from trusthandoff.validation import validate_packet
from trusthandoff.events import get_events, clear_events, dump_events_to_jsonl
from trusthandoff.sentinel import Sentinel
from trusthandoff.overlap import register_overlap


def test_full_protocol_pipeline(tmp_path):
    clear_events()

    issued = datetime.now(timezone.utc)

    # 1. Create packet with TTL + AI provenance
    packet = SignedTaskPacket(
        packet_id="p-e2e",
        task_id="t-e2e",
        from_agent="agent:a",
        to_agent="agent:b",
        issued_at=issued,
        expires_at=issued + timedelta(seconds=1),
        nonce="n",
        intent="test",
        permissions=Permissions(),
        signature_algo="algo",
        signature="sig",
        public_key="pk",
        risk_level="read",
        ttl_seconds=1,
        ai_provenance={"source": "llm", "model": "gpt-test"},
    )

    # 2. Validate (should pass)
    result = validate_packet(packet)
    assert result.is_valid is True

    # 3. Wait expiration
    time.sleep(1.2)

    # 4. Register overlap
    register_overlap(packet.packet_id)

    # 5. Validate again (should pass via overlap)
    result2 = validate_packet(packet)
    assert result2.is_valid is True

    events = get_events()

    # 6. Check events emitted
    event_types = [e["event_type"] for e in events]

    assert "packet_accepted" in event_types
    assert "ai_generated_payload" in event_types
    assert "token_overlap_used" in event_types

    # 7. Export events
    file_path = tmp_path / "events.jsonl"
    dump_events_to_jsonl(str(file_path))

    # 8. Sentinel ingest external
    sentinel = Sentinel()
    sentinel.ingest_jsonl(str(file_path))

    violations = sentinel.detect_violations()

    # Should detect AI + overlap usage
    # detect_violations() returns List[ViolationRecord] as of v0.4.0
    types = [v.violation_type for v in violations]

    assert "ai_generated_payload" in types
    assert "overlap_window_used" in types
