# TrustHandoff

Install:

pip install trusthandoff

TrustHandoff is a lightweight SDK for verifiable task delegation between AI agents.

It provides a canonical structure for transferring tasks between agents with:

- identity
- permissions
- bounded execution
- provenance
- cryptographic signatures

TrustHandoff aims to become a secure delegation layer for multi-agent systems.

---

## Why TrustHandoff exists

Current agent ecosystems solve only part of the problem:

Agent ↔ tools → MCP  
Agent ↔ communication → A2A  
Secure task delegation → missing

TrustHandoff fills this gap by defining a SignedTaskPacket that allows agents to safely hand off tasks.

---

## Delegation flow

```mermaid
flowchart LR
    A[Planner Agent] -->|Create SignedTaskPacket| B[TrustHandoff Packet]
    B --> C[Research Agent]
    C --> D[Execute Task]
```

---

## Installation

pip install trusthandoff

---

## Example

```python
from datetime import datetime, timedelta, timezone
from trusthandoff import SignedTaskPacket, Permissions

packet = SignedTaskPacket(
    packet_id="pk_001",
    task_id="task_001",
    from_agent="agent:planner",
    to_agent="agent:research",
    issued_at=datetime.now(timezone.utc),
    expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    nonce="123",
    intent="Research company background",
    context={"company": "Example Corp"},
    permissions=Permissions(
        allowed_actions=["read", "search"],
        max_tool_calls=5
    ),
    signature_algo="Ed25519",
    signature="signature",
    public_key="public_key"
)
```
---

## Example script

examples/example_agents.py

Run with:

python examples/example_agents.py

---

## Core primitive

TrustHandoff defines a canonical task transfer structure:

SignedTaskPacket

This packet includes:

- task identity
- agent identity
- permissions
- constraints
- provenance
- cryptographic signature

## Current primitives

TrustHandoff v0.2.0 currently includes:

- SignedTaskPacket
- AgentIdentity
- sign_packet()
- verify_packet()
- validate_packet()
- PacketDecision
- process_handoff()
- packet_to_dict()
- packet_from_dict()

---

## Vision

TrustHandoff aims to become the trust layer for agent delegation in multi-agent systems.

Possible integrations:

- LangGraph
- AutoGen
- CrewAI
- OpenAI Agents
- LlamaIndex
- custom agent runtimes

---

## License

MIT
