# Quickstart

Get from `pip install` to a signed, verified, replay-protected packet in under 10 minutes.

---

## Prerequisites

- Python 3.11 or later
- A terminal

---

## Step 1 — Install

```bash
pip install trusthandoff
```

Verify the install:

```bash
python -c "import trusthandoff; print(trusthandoff.__version__)"
```

---

## Step 2 — Generate an identity

Every agent has an Ed25519 keypair. The `agent_id` is derived from the public key hash — you do not assign it manually.

```python
from trusthandoff import AgentIdentity

planner = AgentIdentity.generate()
researcher = AgentIdentity.generate()

print(planner.agent_id)       # agent:a3f8b2c1d4e5f6a7
print(planner.public_key_pem) # -----BEGIN PUBLIC KEY-----\n...
```

---

## Step 3 — Create and sign a packet

A `SignedTaskPacket` is the unit of delegation. It carries the task intent, the permitted actions, the sender and receiver, and a TTL. `sign_packet` adds the Ed25519 signature.

```python
from datetime import datetime, timedelta, timezone
from trusthandoff import (
    AgentIdentity, Permissions, SignedTaskPacket, sign_packet,
)

planner = AgentIdentity.generate()

packet = SignedTaskPacket(
    packet_id="pk-001",
    task_id="task-001",
    from_agent=planner.agent_id,
    to_agent="agent:researcher",
    issued_at=datetime.now(timezone.utc),
    expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    nonce="unique-nonce-001",            # must be globally unique per request
    intent="Research company background",
    context={"company": "Example Corp"},
    permissions=Permissions(
        allowed_actions=["read", "search"],
        max_tool_calls=5,
    ),
    signature_algo="Ed25519",
    signature="",                        # populated by sign_packet
    public_key=planner.public_key_pem,
)

signed = sign_packet(packet, planner)
print(signed.signature[:40])  # base64-encoded Ed25519 signature
```

---

## Step 4 — Verify the signature

`verify_packet` checks the Ed25519 signature against the canonical serialization of the packet. It returns `True` or `False`.

```python
from trusthandoff import verify_packet

is_valid = verify_packet(signed)
assert is_valid is True

print("Signature valid:", is_valid)
```

Tamper with any field and it returns `False`:

```python
from trusthandoff import SignedTaskPacket

tampered = signed.model_copy(update={"intent": "delete all records"})
assert verify_packet(tampered) is False
```

---

## Step 5 — Register identities and bind keys

`verify_packet` on its own trusts the self-reported `public_key`. For production use, supply an `AgentRegistry` so that the verifier cross-checks the key against a known-good binding.

```python
from trusthandoff import AgentRegistry, verify_packet
from trusthandoff.errors import PublicKeyMismatchError

registry = AgentRegistry()
registry.register(planner.agent_id, planner.public_key_pem)

# Verification with registry binding
assert verify_packet(signed, registry=registry) is True

# An attacker substituting a different key is rejected
attacker = AgentIdentity.generate()
registry.register(attacker.agent_id, attacker.public_key_pem)

# Packet claims to be from planner but carries attacker's key
spoofed = signed.model_copy(update={"public_key": attacker.public_key_pem})
try:
    verify_packet(spoofed, registry=registry)
except PublicKeyMismatchError:
    print("Key substitution rejected")
```

---

## Step 6 — Run the full middleware pipeline

The middleware combines signature verification, replay protection, TTL validation, and depth limiting into a single call.

```python
from trusthandoff import (
    DelegationChain, DelegationEnvelope, TrustHandoffMiddleware,
)

# Wrap the signed packet in an envelope with a delegation chain
chain = DelegationChain(
    packet_ids=[signed.packet_id],
    agents=[planner.agent_id],
)
envelope = DelegationEnvelope(packet=signed, chain=chain)

middleware = TrustHandoffMiddleware(max_depth=5)

decision = middleware.handle(envelope)
print(decision.decision)  # ACCEPT

# The nonce is now recorded. A replay is rejected.
replay_decision = middleware.handle(envelope)
print(replay_decision.decision)  # REJECT
print(replay_decision.reason)    # Replay detected
```

---

## Step 7 — Validate the packet

`validate_packet` runs the full packet-level checks: time window, TTL policy, human review requirement, AI provenance.

```python
from trusthandoff import validate_packet

result = validate_packet(signed, registry=registry)
print(result.is_valid)  # True
print(result.reason)    # None — packet is valid
```

If a packet has expired:

```python
from datetime import datetime, timedelta, timezone
from trusthandoff import SignedTaskPacket, Permissions, validate_packet

issued = datetime.now(timezone.utc) - timedelta(hours=1)
expired_packet = SignedTaskPacket(
    packet_id="pk-expired",
    task_id="task-expired",
    from_agent="agent:a",
    to_agent="agent:b",
    issued_at=issued,
    expires_at=issued + timedelta(seconds=30),  # expired 30 minutes ago
    nonce="nonce-expired",
    intent="stale task",
    permissions=Permissions(),
    signature_algo="Ed25519",
    signature="sig",
    public_key="pk",
)

result = validate_packet(expired_packet)
print(result.is_valid)  # False
print(result.reason)    # packet_expired
```

---

## What's next

| Topic | Guide |
|-------|-------|
| Risk-based TTL (`write` vs `read` operations) | See `policy.py` and `DEFAULT_POLICY` |
| Human review gates | `Constraints(requires_human_review=True)` + `context["human_approval"]` |
| Redis for distributed replay protection | `RedisReplayBackend` in `replay.py` |
| Forensic auditing | `Sentinel` in `sentinel.py` + `dump_events_to_jsonl` |
| Capability revocation mid-execution | `CapabilityRevocationRegistry` + `handle_with_revalidation` |
| AI provenance tagging | `SignedTaskPacket(ai_provenance={"source": "llm", ...})` |

Full API reference: [README](../../README.md)
Security invariants: [SECURITY.md](../../SECURITY.md)
