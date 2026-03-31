# Changelog

All notable changes to TrustHandoff are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.4] — 2026-03-31

### Security

- **Registry-backed public key binding** — `verify_packet` and `validate_packet` now enforce that `packet.public_key` matches the key registered for `packet.from_agent` in the `AgentRegistry`. A packet carrying a mismatched key raises `PublicKeyMismatchError` rather than returning `False` silently. Closes the key substitution vector identified in the known fragile points audit.
- **Deterministic serialization enforced end-to-end** — all signing paths confirmed to use `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. `model_dump_json` is no longer used anywhere in the signing or verification pipeline.

### Fixed

- **Sentinel threading race condition** — `Sentinel.events` is now protected by a `threading.Lock`. Previously, concurrent calls to `ingest()` and `detect_violations()` could observe a partially-mutated list, producing spurious or missed violations.

---

## [0.3.3] — 2026-03-XX

### Added

- **Risk-based TTL enforcement** — `SignedTaskPacket` accepts `risk_level` (`"write"` or `"read"`). The default policy maps `write → 120 s` and `read → 900 s`. A packet whose `expires_at` does not match the policy for its `risk_level` is rejected at construction — not at runtime.
- **TTL bound to packet** — `ttl_seconds` is stored on the packet and checked by `validate_packet`. A validator mismatch is a hard rejection.
- **Strict mode** — set `TRUSTHANDOFF_ENFORCE_DEFAULT_TTL_POLICY=1` to reject packets that do not carry a `risk_level` at all.
- **Runtime revalidation watcher** — `TrustHandoffMiddleware.handle_with_revalidation()` spawns a background thread that re-runs a caller-supplied `revalidate_fn` on a configurable interval. Revoked or expired capabilities are caught mid-execution.
- **Human review gates** — `Constraints(requires_human_review=True)` causes `validate_packet` to reject the packet unless `context["human_approval"]` is present. Blocking, enforced at the protocol level.
- **Overlap window safety** — a 30-second overlap window allows token rotation without a replay-rejection gap. `register_overlap(packet_id)` marks a packet as overlap-eligible; `Sentinel` flags overlap usage in the audit trail.
- **Structured event bus** — `emit_event`, `get_events`, `clear_events`, `dump_events_to_jsonl`, and `load_events_from_jsonl` provide an in-process event buffer. Pluggable sinks: `KafkaEventSink` for ordered durable publishing.
- **AI provenance tagging** — `SignedTaskPacket.ai_provenance: Dict[str, Any]` tags packets that originate from LLM output. `validate_packet` emits an `ai_generated_payload` event; `Sentinel` surfaces it as a violation category.
- **Sentinel forensic auditor** — `Sentinel.ingest()` / `ingest_jsonl()` loads event streams; `detect_violations()` returns structured violation records for: `rejected_packet`, `stale_capability`, `overlap_window_used`, `ai_generated_payload`. `report()` prints a human-readable summary.
- **Capability revocation** — `CapabilityRevocationRegistry` with `InMemoryRevocationBackend` and `RedisRevocationBackend`. `set_revocation_backend()` configures the global instance.

### Changed

- `verify_packet` signature extended: optional `registry: AgentRegistry` parameter. When provided, cross-checks `packet.public_key` against the registered key for `packet.from_agent`.
- `validate_packet` signature extended: optional `registry` parameter forwarded to `verify_packet`.
- `TrustHandoffMiddleware.handle()` returns `PacketDecision` (previously returned a plain dict in internal builds).

### Fixed

- Clock skew tolerance is now configurable via `TRUSTHANDOFF_ISSUANCE_SKEW` (0–300 s, default 30 s) and `TRUSTHANDOFF_EXPIRY_GRACE` (0–60 s, default 0 s) environment variables.
- `sign_packet` now always signs the post-validator packet — `expires_at` is guaranteed to be set before the payload is serialized.

---

## Earlier Releases

Versions prior to 0.3.3 are not documented in this file.
See git history for change details.
