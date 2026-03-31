<p align="center">
  <a href="https://scorecard.dev/viewer/?uri=github.com/trusthandoff/trusthandoff"><img src="https://api.scorecard.dev/projects/github.com/trusthandoff/trusthandoff/badge" alt="OpenSSF Scorecard"/></a>
  <a href="https://pypi.org/project/trusthandoff/"><img src="https://img.shields.io/pypi/v/trusthandoff.svg" alt="PyPI version"/></a>
  <a href="https://pypi.org/project/trusthandoff/"><img src="https://img.shields.io/pypi/pyversions/trusthandoff.svg" alt="Python versions"/></a>
  <a href="https://github.com/trusthandoff/trusthandoff/blob/main/LICENSE"><img src="https://img.shields.io/pypi/l/trusthandoff.svg" alt="License"/></a>
  <a href="https://github.com/trusthandoff/trusthandoff/actions"><img src="https://img.shields.io/badge/supply%20chain-Sigstore%20%2B%20SLSA-green" alt="Supply Chain"/></a>
</p>

# TrustHandoff

**TLS for agents — but extended to execution.**

TLS secures communication. TrustHandoff secures what happens after the message arrives.

Every task delegation is signed. Every handoff is replay-resistant. Every execution is attestable.
If you cannot prove execution, you cannot trust the system.

---

## ⚔️ Attack Demo

<p align="center">
  <img src="demoattack_trusthandoff_gif.gif" width="600"/>
</p>

> Legit output → accepted
> Tampered output → rejected
> Replay → rejected

**Execution without proof is trust theater.**

---

## The Problem

Modern agent systems trust execution by convention:

- Intermediate outputs are passed blindly between agents
- Permissions are long-lived and rarely scoped
- Replayed or tampered packets produce no signal
- When something goes wrong, there is no audit trail

The weakest point is not the model. It is the handoff.

---

## What TrustHandoff Does

```
┌─────────────────────────────────────────────────────────────────┐
│                     Agent A (Planner)                           │
│  1. Creates SignedTaskPacket with scoped Permissions + TTL      │
│  2. Signs with Ed25519 private key                              │
│  3. Attaches nonce, issued_at, expires_at, risk_level           │
└──────────────────────────┬──────────────────────────────────────┘
                           │  DelegationEnvelope (packet + chain)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                   TrustHandoffMiddleware                        │
│  ✓ verify_packet     — Ed25519 signature + registry binding     │
│  ✓ replay check      — nonce seen before? REJECT                │
│  ✓ validate_packet   — TTL, clock skew, human review, AI tag    │
│  ✓ depth limit       — delegation chain too long? REJECT        │
│  ✓ revocation check  — capability revoked mid-flight? REJECT    │
│  → PacketDecision: ACCEPT or REJECT + reason                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │  ACCEPT
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Agent B (Executor)                          │
│  - Executes only after gate passes                              │
│  - Emits structured events for audit trail                      │
│  - Sentinel detects violations post-execution                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Install

```bash
pip install trusthandoff
```

Requires Python ≥ 3.11. No mandatory external services — Redis is optional for distributed deployments.

Releases are published from GitHub Actions using Trusted Publishing and include verifiable build provenance via Sigstore + SLSA attestations.

---

## Quickstart

### 1. Sign and verify a delegation packet

```python
from datetime import datetime, timedelta, timezone
from trusthandoff import (
    AgentIdentity, Permissions, SignedTaskPacket,
    sign_packet, verify_packet,
)

# Each agent has an Ed25519 keypair. agent_id is derived from the public key hash.
planner = AgentIdentity.generate()

packet = SignedTaskPacket(
    packet_id="pk-001",
    task_id="task-001",
    from_agent=planner.agent_id,
    to_agent="agent:researcher",
    issued_at=datetime.now(timezone.utc),
    expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    nonce="unique-nonce-001",
    intent="Research company background",
    context={"company": "Example Corp"},
    permissions=Permissions(allowed_actions=["read", "search"], max_tool_calls=5),
    signature_algo="Ed25519",
    signature="",           # populated by sign_packet
    public_key=planner.public_key_pem,
)

signed = sign_packet(packet, planner)
assert verify_packet(signed) is True
```

### 2. Registry binding — prevent key substitution attacks

```python
from trusthandoff import AgentRegistry, verify_packet

registry = AgentRegistry()
registry.register(planner.agent_id, planner.public_key_pem)

# verify_packet cross-checks packet.public_key against the registry.
# A packet carrying a different key for the same agent_id raises PublicKeyMismatchError.
assert verify_packet(signed, registry=registry) is True
```

### 3. Full middleware pipeline — replay protection + validation in one pass

```python
from trusthandoff import (
    AgentIdentity, DelegationChain, DelegationEnvelope,
    Permissions, SignedTaskPacket, TrustHandoffMiddleware, sign_packet,
)

planner = AgentIdentity.generate()
researcher = AgentIdentity.generate()

packet = SignedTaskPacket(
    packet_id="pk-flow-001",
    task_id="task-flow-001",
    from_agent=planner.agent_id,
    to_agent=researcher.agent_id,
    issued_at=datetime.now(timezone.utc),
    expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    nonce="nonce-flow-001",
    intent="Summarize research findings",
    context={},
    permissions=Permissions(allowed_actions=["read", "summarize"], max_tool_calls=3),
    signature_algo="Ed25519",
    signature="",
    public_key=planner.public_key_pem,
)

signed = sign_packet(packet, planner)

chain = DelegationChain(packet_ids=[signed.packet_id], agents=[planner.agent_id])
envelope = DelegationEnvelope(packet=signed, chain=chain)

middleware = TrustHandoffMiddleware(max_depth=5)

decision = middleware.handle(envelope)
assert decision.decision == "ACCEPT"

# Same envelope a second time: nonce already seen → rejected
replay_decision = middleware.handle(envelope)
assert replay_decision.decision == "REJECT"
assert replay_decision.reason == "Replay detected"
```

### 4. Risk-based TTL — write operations get shorter lifetimes

```python
from trusthandoff import SignedTaskPacket, Permissions, validate_packet

# DEFAULT_POLICY: write=120s, read=900s
# Setting risk_level enforces the matching TTL at construction time.
issued = datetime.now(timezone.utc)

write_packet = SignedTaskPacket(
    packet_id="pk-write",
    task_id="task-write",
    from_agent="agent:a",
    to_agent="agent:b",
    issued_at=issued,
    expires_at=issued + timedelta(seconds=120),   # must match write policy
    nonce="nonce-write-001",
    intent="update_record",
    permissions=Permissions(),
    signature_algo="Ed25519",
    signature="sig",
    public_key="pk",
    risk_level="write",
)

result = validate_packet(write_packet)
assert result.is_valid is True

# TTL that exceeds the policy is rejected at construction — not at runtime.
# SignedTaskPacket(..., risk_level="write", expires_at=issued + timedelta(seconds=999))
# → raises ValueError: expires_at does not match TTL policy (risk_level=write, ttl_seconds=120)
```

### 5. Human review gates + AI provenance tagging

```python
from trusthandoff import (
    AgentIdentity, AgentRegistry, Constraints, Permissions,
    SignedTaskPacket, sign_packet, validate_packet,
)

identity = AgentIdentity.generate()
registry = AgentRegistry()
registry.register(identity.agent_id, identity.public_key_pem)

issued = datetime.now(timezone.utc)

# requires_human_review=True: validation fails unless context["human_approval"] is set.
# ai_provenance: tags the packet as AI-generated for Sentinel detection.
packet = SignedTaskPacket(
    packet_id="pk-hr-001",
    task_id="task-hr-001",
    from_agent=identity.agent_id,
    to_agent="agent:executor",
    issued_at=issued,
    expires_at=issued + timedelta(minutes=5),
    nonce="nonce-hr-001",
    intent="deploy_change",
    permissions=Permissions(),
    constraints=Constraints(requires_human_review=True),
    context={},                                          # no approval yet
    signature_algo="Ed25519",
    signature="",
    public_key=identity.public_key_pem,
    ai_provenance={"source": "llm", "model": "gpt-4"},
)

signed = sign_packet(packet, identity)
result = validate_packet(signed, registry=registry)
assert result.is_valid is False
assert result.reason == "human_review_required"
```

### 6. Sentinel — forensic violation detection

```python
from trusthandoff.events import dump_events_to_jsonl
from trusthandoff.sentinel import Sentinel

# After any execution flow, dump the event buffer and run the auditor.
dump_events_to_jsonl("/tmp/audit.jsonl")

sentinel = Sentinel()
sentinel.ingest_jsonl("/tmp/audit.jsonl")

violations = sentinel.detect_violations()
# Detects: rejected_packet, stale_capability, overlap_window_used, ai_generated_payload

sentinel.report()   # prints structured violation summary to stdout
```

---

## Security Model

TrustHandoff enforces five non-negotiable invariants. Every release is audited against them.

| # | Invariant | Where enforced |
|---|-----------|----------------|
| 1 | **Deterministic serialization** — `json.dumps(..., sort_keys=True)` before signing; `model_dump_json` is never used on signed payloads | `signing.py`, `verification.py` |
| 2 | **No tracebacks in signed payloads** — runtime artifacts are stripped before any field enters the signing payload | `packet.py` |
| 3 | **Public key is not a trust anchor** — `packet.public_key` is self-reported; the registry is always cross-checked before accepting a packet | `verification.py`, `agent_registry.py` |
| 4 | **Sign after validators run** — `model_validator(mode="after")` sets `expires_at`; signing before Pydantic construction completes produces a stale payload | `signing.py`, `packet.py` |
| 5 | **Typed error hierarchy** — security failures raise typed exceptions (`InvalidSignatureError`, `ReplayAttackError`, `PublicKeyMismatchError`, …), never bare `ValueError` or string-parsed `Exception` | `errors.py` |

### Error types

```python
from trusthandoff.errors import (
    TrustHandoffError,        # base
    VerificationError,        # signature verification failed
    InvalidSignatureError,    # bad Ed25519 signature
    ReplayAttackError,        # nonce reuse detected
    PublicKeyMismatchError,   # registry binding failed
    PayloadValidationError,   # packet fields invalid
    StaleCapabilityError,     # capability revoked or expired mid-task
    CapabilityError,          # capability constraint violated
    AttestationError,         # execution attestation failed
)
```

---

## Architecture

```
trusthandoff/
├── packet.py            SignedTaskPacket — core data model, TTL validator
├── identity.py          AgentIdentity — Ed25519 keypair + agent_id derivation
├── signing.py           sign_packet — canonical JSON → Ed25519 sign
├── verification.py      verify_packet — signature + registry binding
├── validation.py        validate_packet — TTL, clock skew, human review, AI tag
├── replay.py            ReplayBackend — InMemory + Redis (SETNX)
├── replay_guard.py      orchestrates replay check + verification
├── revocation.py        CapabilityRevocationRegistry — InMemory + Redis
├── agent_registry.py    AgentRegistry — agent_id → public_key_pem
├── sentinel.py          Sentinel — forensic event log + violation detection
├── overlap.py           overlap window safety for token rotation
├── revalidation.py      runtime revalidation watcher
├── events.py            structured event bus (JSONL, Kafka sink)
├── errors.py            typed exception hierarchy
├── middleware/
│   ├── engine.py        TrustHandoffMiddleware — full pipeline orchestration
│   ├── executor.py      TrustHandoffExecutor — execution gating
│   ├── pipeline.py      step sequencing
│   ├── steps.py         individual middleware steps
│   └── decision.py      PacketDecision — ACCEPT / REJECT
├── chain.py             DelegationChain — depth tracking
├── envelope.py          DelegationEnvelope — packet + chain container
└── decorators.py        @signed_task — policy metadata attachment
```

### Fits into your existing stack

| Layer | Tool | Role |
|-------|------|------|
| Tools | MCP | What agents can call |
| Communication | A2A | How agents talk |
| Orchestration | LangGraph / CrewAI / AutoGen | When agents run |
| **Delegation + integrity** | **TrustHandoff** | **Proof that execution happened as delegated** |

### Redis for distributed deployments

```python
from trusthandoff.replay import RedisReplayBackend, set_replay_backend
from trusthandoff.revocation import RedisRevocationBackend, set_revocation_backend

set_replay_backend(RedisReplayBackend("redis://localhost:6379", ttl_seconds=3600))
set_revocation_backend(RedisRevocationBackend("redis://localhost:6379"))
```

---

## What's New in v0.3.4

- Registry-backed `public_key` binding enforced in `verify_packet` and `validate_packet` — closes the key substitution vector
- Threading lock on `Sentinel.events` eliminates race condition in `detect_violations()`
- Deterministic serialization enforced end-to-end — `sort_keys=True` in all signing paths

### v0.3.3 highlights

- Risk-based TTL: `write=120s`, `read=900s` — mismatch rejected at construction
- Runtime revalidation watcher — detects capability drift mid-execution
- Human review gates — blocking, enforced at protocol level
- Overlap window (30 s) — prevents race conditions during token rotation
- Structured event system + JSONL export for audit trails
- Sentinel violation detection: replay attempts, stale capabilities, AI-generated payloads

---

## Roadmap

| Status | Item |
|--------|------|
| Done | Ed25519 signing + verification |
| Done | Nonce-based replay protection (in-memory + Redis) |
| Done | Risk-based TTL enforcement |
| Done | Human review gates |
| Done | Capability revocation (in-memory + Redis) |
| Done | AI provenance tagging |
| Done | Overlap window safety |
| Done | Sentinel forensic auditing |
| Done | JSONL + Kafka event sinks |
| Planned | Distributed nonce tracking across agent clusters |
| Planned | Shared revocation registries |
| Planned | Cross-agent invalidation on capability revoke |
| Planned | Network-aware trust boundary enforcement |
| Planned | OpenTelemetry trace integration |

---

## Contributing

Contributions are welcome. A few things to know before opening a PR:

**Security-critical files** — any change to `signing.py`, `verification.py`, `replay.py`, `replay_guard.py`, `revocation*.py`, or `packet.py` requires a written plan first. State the invariant being preserved and the test that proves it after the change.

**Run the tests before opening a PR:**

```bash
cd /path/to/trusthandoff
pytest tests/ -v
# focused crypto tests
pytest tests/test_signing.py tests/test_verification.py tests/test_replay.py -v
```

**Error handling** — use the typed hierarchy in `errors.py`. Do not raise bare `ValueError` or parse exception message strings for security-relevant failures.

**Adding fields to `SignedTaskPacket`** — audit the serialization impact first. Any new `Dict[str, Any]` field must be covered by the deterministic serialization path.

Open an issue to discuss larger changes before writing code.

---

## License

MIT
