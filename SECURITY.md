# Security Policy

## Official Sources

The official TrustHandoff repository is `https://github.com/trusthandoff/trusthandoff`.

Releases are published through GitHub Actions Trusted Publishing to PyPI from the official repository only.
Every release includes verifiable build provenance via [Sigstore](https://sigstore.dev) and [SLSA](https://slsa.dev) attestations.

```bash
pip install sigstore
sigstore verify github --cert-identity \
  https://github.com/trusthandoff/trusthandoff/.github/workflows/publish.yml@refs/heads/main \
  trusthandoff-*.whl
```

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| < 0.3   | No        |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report privately through [GitHub Security Advisories](https://github.com/trusthandoff/trusthandoff/security/advisories/new)
or contact the maintainer directly at `266288756+shaymizuno@users.noreply.github.com`.

Include: a description of the issue, reproduction steps, and the version affected.
We will acknowledge receipt promptly and provide a resolution timeline before public disclosure.

In scope: signature verification, delegation validation, capability/token handling, trust boundaries between agents, supply-chain integrity.

---

## Security Model

TrustHandoff enforces five invariants. Any code path that violates one of them is a security bug,
regardless of whether a working exploit has been demonstrated.

---

### Invariant 1 — Deterministic serialization

**Rule:** The signing payload must be produced by:

```python
import json

payload = json.dumps(
    packet.model_dump(exclude={"signature"}, mode="json"),
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
).encode("utf-8")
```

`model_dump_json` is never used on signed payloads.

**Why it matters:** `SignedTaskPacket` contains `context: Dict[str, Any]` and `ai_provenance: Dict[str, Any]`. Python dicts preserve insertion order, which is not guaranteed to be the same between the signing agent and the verifying agent. Any key-order divergence produces a silent `False` from `verify_packet` — no exception, no log entry, just broken trust. `sort_keys=True` eliminates the insertion-order dependency.

**Files:** `signing.py`, `verification.py`, `serialization.py`

---

### Invariant 2 — No tracebacks in signed payloads

**Rule:** Tracebacks and other runtime artifacts must never appear in any field that is included in the signing payload.

**Why it matters:** Tracebacks contain stack frames, file paths, and timing data that are produced at runtime and not reproducible. If a traceback enters a signed field, the verifier computes a different hash than the signer, causing verification to fail silently — or, worse, a traceback becomes part of an authenticated payload that was never intended for transmission.

Fields that can carry exception information must be explicitly excluded from `model_dump(exclude=...)` or stripped before signing.

**Files:** `packet.py`, `signing.py`

---

### Invariant 3 — `public_key` is self-reported — never the trust anchor

**Rule:** `packet.public_key` is supplied by the sender and must not be trusted on its own. Any code path that accepts a packet as authentic solely because its signature validates against its embedded public key is a vulnerability.

The `AgentRegistry` (or an external store) is the source of truth for the binding `from_agent → public_key`. `verify_packet` must be called with a `registry` argument whenever the caller does not already hold an out-of-band-verified key for the sender.

```python
# Unsafe — trusts the self-reported key
verify_packet(packet)

# Safe — cross-checks against the registry
verify_packet(packet, registry=registry)
```

A mismatch raises `PublicKeyMismatchError`. It is never silently ignored.

**Files:** `verification.py`, `agent_registry.py`

---

### Invariant 4 — Sign after all validators have run

**Rule:** `sign_packet` must always be called after Pydantic model construction is complete.

**Why it matters:** `SignedTaskPacket` uses `model_validator(mode="after")` to populate `expires_at` from TTL policy when it is not supplied explicitly. Signing before Pydantic has finished running validators produces a payload where `expires_at` is `None`. A verifier that reconstructs the canonical payload will include the final `expires_at` value, so the signatures will not match — or the packet will be accepted with a missing expiry.

```python
# Correct: construct first (validators run), then sign
packet = SignedTaskPacket(...)
signed = sign_packet(packet, identity)
```

**Files:** `signing.py`, `packet.py`

---

### Invariant 5 — Typed error hierarchy — no string parsing

**Rule:** Security-relevant failures must raise a specific exception from the typed hierarchy in `errors.py`. `Exception` and `ValueError` must not be raised for these paths. Callers must not catch `Exception` and inspect the message string to determine what failed.

```
TrustHandoffError
├── VerificationError
│   ├── InvalidSignatureError      # Ed25519 verification failed
│   ├── ReplayAttackError          # nonce already seen
│   └── PublicKeyMismatchError     # registry binding failed
├── PayloadValidationError         # packet fields invalid
├── CanonicalizationError          # JSON encoding failed
├── AttestationError               # execution attestation failed
├── CapabilityError
│   ├── StaleCapabilityError       # capability revoked or expired mid-task
│   └── RevocationConsistencyError # revocation state inconsistent
└── AdapterError
    ├── MissingPacketIDError
    └── MiddlewareExecutionError
```

**Why it matters:** String-parsed errors break under refactoring, are untestable, and make it impossible for callers to distinguish between failure modes programmatically.

**File:** `errors.py`
