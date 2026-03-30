# CLAUDE.md — TrustHandoff

## What this is

Cryptographic delegation and accountability SDK for multi-agent AI systems.
Ed25519 signing, nonce+timestamp replay protection, delegation depth limits,
execution attestation, capability scoping.

**If you cannot prove execution, you cannot trust the system.**

-----

## Security Invariants — Non-Negotiable

These rules override everything. Never bypass, never “temporarily” relax.

### 1. Deterministic serialization

`model_dump_json` is NOT safe for signing payloads. Always use:

```python
import json
payload = json.dumps(
    packet.model_dump(exclude={"signature"}, mode="json"),
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True
).encode("utf-8")
```

Rationale: `context: Dict[str, Any]` and `ai_provenance` have undefined key
order. Any insertion-order divergence between signer and verifier produces a
silent False from verify_packet — no exception, no log, just broken trust.

### 2. Never put tracebacks in signed payloads

Tracebacks are runtime artifacts. They must never enter any field that is
included in the signing payload. If a field can contain exception info,
exclude it explicitly or strip before signing.

### 3. public_key is self-reported — treat it accordingly

The packet carries its own public_key. This is NOT a trust anchor.
The identity registry (AgentIdentity / external store) is the source of truth
for from_agent → public_key binding. Any code path that trusts packet.public_key
without cross-checking the registry is a vulnerability.

### 4. Sign after all validators have run

model_validator(mode=“after”) mutates expires_at in-place.
Always sign the packet AFTER Pydantic construction is complete.
Signing a pre-validator packet means expires_at=None in the payload —
verification will fail or worse, silently accept a stale packet.

### 5. Typed error hierarchy — no string parsing

Never catch Exception and parse the message string.
Never raise bare Exception or ValueError for security-relevant failures.
Use the typed hierarchy in errors.py. Add new types before adding new strings.

-----

## Architecture Map

```
src/trusthandoff/
├── packet.py           # SignedTaskPacket — core data model + TTL validator
├── signing.py          # sign_packet — Ed25519 sign
├── verification.py     # verify_packet — Ed25519 verify
├── replay.py           # ReplayBackend — InMemory + Redis (SETNX)
├── replay_guard.py     # orchestrates replay check + verification
├── revalidation.py     # runtime revalidation of live packets
├── revocation.py       # revocation store
├── revocation_validation.py
├── sentinel.py         # forensic event log + violation detection
├── overlap.py          # overlap window safety
├── policy.py           # DEFAULT_POLICY, risk_level → TTL mapping
├── validation.py       # packet-level validation pipeline
├── middleware/
│   ├── engine.py       # middleware orchestration
│   ├── pipeline.py     # step sequencing
│   ├── executor.py     # execution gating
│   ├── decision.py     # allow/deny decision
│   └── steps.py        # individual middleware steps
├── wire.py             # serialization for transport
├── serialization.py    # canonical serialization helpers
├── loop.py             # agent execution loop
├── packet_propagation.py
└── identity.py         # AgentIdentity, keypair management
```

-----

## Known Fragile Points (audit before touching)

|File                        |Issue                                                      |Risk  |
|----------------------------|-----------------------------------------------------------|------|
|signing.py + verification.py|model_dump_json non-deterministic on dicts                 |HIGH  |
|sentinel.py                 |~~No lock on self.events during detect_violations() iteration~~ Fixed: threading.Lock added|LOW   |
|packet.py                   |public_key self-reported, no registry binding enforced     |HIGH  |
|middleware/executor.py      |Verify execution gating is atomic — check for TOCTOU       |MEDIUM|

-----

## Workflow Rules

### Plan before touching security-critical files

For any change to: signing.py, verification.py, replay.py, replay_guard.py,
revocation*.py, packet.py — write a plan first. State:

- What invariant you’re preserving
- What test proves it after the change

### Test commands

```bash
cd /root/trusthandoff
pytest tests/ -v
pytest tests/test_signing.py tests/test_verification.py tests/test_replay.py -v
```

### Never mark done without running tests

Especially for crypto changes. “Looks right” is not a verification.

### Self-improvement

After any correction: update tasks/lessons.md with the pattern.
Review lessons.md at session start.

-----

## Task Management

- Plan → tasks/todo.md (checkable items)
- Lessons → tasks/lessons.md (patterns from corrections)
- Never temp-fix. Find root cause. Senior engineer standard.

-----

## Out of Scope for Claude Code

- Never modify DEFAULT_POLICY risk levels without explicit user confirmation
- Never change the signing algorithm (Ed25519) without a full migration plan
- Never add fields to SignedTaskPacket without auditing serialization impact
