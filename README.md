# TrustHandoff

TrustHandoff is a lightweight protocol and SDK for **verifiable task delegation between AI agents**.

It defines a canonical structure for transferring tasks between agents with:

- agent identity
- cryptographic signatures
- bounded execution permissions
- delegation chains
- verifiable decision logic

TrustHandoff acts as a **delegation trust layer** for multi-agent systems.

---

# Why TrustHandoff exists

Modern agent frameworks solve orchestration and communication.

They do not solve **verifiable delegation**.

| Layer | Example |
|------|------|
| Agent ↔ tools | MCP |
| Agent ↔ communication | A2A |
| Agent orchestration | LangGraph / CrewAI / AutoGen |
| **Agent delegation trust** | TrustHandoff |

TrustHandoff introduces a portable delegation primitive:

```
SignedTaskPacket
```

This packet allows agents to safely hand off tasks while preserving:

- authority
- permissions
- provenance
- cryptographic verification

---

## Positioning

TrustHandoff is a delegation trust layer for multi-agent systems.

It is not:
- a transport protocol
- a message bus
- an orchestration framework
- a replacement for LangGraph, CrewAI, AutoGen, A2A, or MCP

TrustHandoff complements these systems by adding:

- verifiable delegation
- bounded authority
- provenance-aware handoff
- replay protection
- multi-hop authority validation

Recommended ecosystem framing:

- MCP = tools / context
- A2A = agent communication
- LangGraph / CrewAI / AutoGen = orchestration
- TrustHandoff = delegation trust layer

---

# Installation

```
pip install trusthandoff

```
---

# Quickstart

Minimal example:

```python
from datetime import datetime, timedelta, timezone
from trusthandoff import (
    AgentIdentity,
    Permissions,
    SignedTaskPacket,
    sign_packet,
    verify_packet,
    process_handoff
)

planner = AgentIdentity.generate()
research = AgentIdentity.generate()

packet = SignedTaskPacket(
    packet_id="pk_example",
    task_id="task_example",
    from_agent=planner.agent_id,
    to_agent=research.agent_id,
    issued_at=datetime.now(timezone.utc),
    expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    nonce="nonce-example",
    intent="Research company background",
    context={"company": "Example Corp"},
    permissions=Permissions(
        allowed_actions=["read", "search"],
        max_tool_calls=5
    ),
    signature_algo="Ed25519",
    signature="",
    public_key=planner.public_key_pem
)

signed_packet = sign_packet(packet, planner)

verify_packet(signed_packet)

decision = process_handoff(signed_packet)

print(decision.decision)
print(decision.reason)
```

Expected output:

```
ACCEPT
Packet verified and valid
```

---

# Core primitives

TrustHandoff revolves around four primitives:

```
SignedTaskPacket
DelegationEnvelope
DelegationChain
PacketDecision
```

These primitives allow verifiable multi-hop delegation between agents.

---

# Framework adapters

TrustHandoff provides adapters for major agent frameworks.

Current adapters:

- CrewAI
- AutoGen
- LangGraph

These adapters map framework-native delegation events into TrustHandoff primitives.

See:

```
specs/adapters.md
```

---

# Specification

Protocol specifications:

```
specs/trusthandoff-spec-v0.1.md
specs/trusthandoff-spec-v0.2.md
```

---

# Examples

Example flows are available in:

```
examples/
```

---

# Vision

TrustHandoff aims to become the **trust layer for delegation in multi-agent systems**.

Rather than replacing agent frameworks, TrustHandoff complements them by providing a secure delegation primitive.

---

# Security Pipeline

TrustHandoff enforces a secure delegation pipeline through its middleware.

The verification pipeline is:

---

# Threat Model

TrustHandoff is designed to prevent the following attacks during agent-to-agent delegation:

- **Impersonation**  
  Unsigned or forged packets → signature verification fails

- **Unbounded delegation**  
  Unlimited recursion or tool access → bounded permissions + max depth enforced

- **Context poisoning**  
  Malicious context injection → provenance chain allows auditing back to origin

- **Replay attacks**  
  Re-use of old packets → nonce + replay protection

- **Lost ownership**  
  Delegated agent claims authority it doesn't have → delegation chain + signer verification

Out of scope (for now):

- side-channel key extraction
- denial-of-service against verification
- physical key theft

---

# License

MIT

---

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/trusthandoff)](https://pypi.org/project/trusthandoff/)
