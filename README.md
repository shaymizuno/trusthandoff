[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/trusthandoff/trusthandoff/badge)](https://scorecard.dev/viewer/?uri=github.com/trusthandoff/trusthandoff)

[![PyPI version](https://img.shields.io/pypi/v/trusthandoff.svg)](https://pypi.org/project/trusthandoff/)

[![Python versions](https://img.shields.io/pypi/pyversions/trusthandoff.svg)](https://pypi.org/project/trusthandoff/)

[![License](https://img.shields.io/pypi/l/trusthandoff.svg)](https://github.com/trusthandoff/trusthandoff/blob/main/LICENSE)

[![Supply Chain](https://img.shields.io/badge/supply%20chain-Sigstore%20%2B%20SLSA-green)](https://github.com/trusthandoff/trusthandoff/actions)
Releases are published from GitHub Actions using Trusted Publishing and include verifiable build provenance / attestations.

## ⚔️ Attack Demo

<p align="center">
  <img src="demoattack_trusthandoff_gif.gif" width="600"/>
</p>

> Legit output → accepted  
> Tampered output → rejected  
> Replay → rejected  

**Execution without proof is trust theater.**

# TrustHandoff

Most agent systems trust execution by convention.

TrustHandoff makes it provable.

---

## What this is

TrustHandoff is a protocol layer for verifiable delegation and execution integrity in AI agent systems.

Think TLS for agents — but extended to execution.

TLS secures communication.

TrustHandoff secures execution.

---

## The problem

In modern agent systems:

- intermediate outputs are trusted blindly
- permissions are long-lived and rarely enforced
- replay and tampering are not first-class concerns
- execution cannot be audited or proven

The weakest point is not the model.

It is the handoff.

---

## What TrustHandoff does

TrustHandoff adds:

- signed, time-bounded task delegation
- replay protection via nonce tracking
- runtime revalidation of capabilities
- strict TTL enforcement (risk-based)
- human execution gates
- AI provenance tagging
- overlap window safety for token rotation
- event-based observability
- post-execution forensic analysis (Sentinel)

---

## Core guarantees

Every execution becomes:

- tamper-evident
- replay-resistant
- runtime-verifiable

---

## Example

1. PLANNER NODE -> verification: True  
2. RESEARCHER NODE -> verification: True  
3. TAMPERED HANDOFF -> verification: False  
4. REPLAYED HANDOFF -> verification: False  

---

## What’s new in v0.3.3

This release closes the execution integrity loop.

### Enforcement

- risk-based TTL (write=120s, read=900s)
- TTL bound to packet
- mismatch rejected at validation
- optional strict mode for production

### Runtime integrity

- revalidation watcher detects drift mid-execution
- revoked or expired capabilities are rejected
- replay protection enforced

### Execution control

- human review gates (blocking)
- capability constraints enforced at protocol level

### Safety

- overlap window (30s) for token rotation
- prevents race conditions

### Observability

- structured event system
- JSONL export for audit trails
- pluggable event sinks

### Detection

- Sentinel detects:
  - replay attempts
  - stale capabilities
  - overlap usage
  - AI-generated payloads

---

## Architecture

TrustHandoff plugs into existing stacks:

- MCP = tools  
- A2A = communication  
- LangGraph / CrewAI / AutoGen = orchestration  
- TrustHandoff = delegation + execution integrity  

---

## Current scope

- local replay protection (Redis-ready)
- runtime revalidation
- TTL enforcement
- execution gating
- overlap safety
- event-driven observability
- forensic detection (Sentinel)

---

## Direction

TrustHandoff is evolving into a distributed execution integrity layer for agent systems.

Planned:

- distributed nonce tracking
- shared revocation registries
- cross-agent invalidation
- network-aware trust boundaries

---

## Philosophy

If you cannot prove execution, you cannot trust the system.

---

## License

MIT
