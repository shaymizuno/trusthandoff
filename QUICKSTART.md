# TrustHandoff Quickstart

This quickstart shows the minimal flow required to use TrustHandoff.

The core idea is simple:

create packet → sign packet → verify packet → process handoff

---

## Install

```bash
pip install trusthandoff
from datetime import datetime, timedelta, timezone
from trusthandoff import (
    AgentIdentity,
    Permissions,
    SignedTaskPacket,
    sign_packet,
    verify_packet,
    process_handoff
)
```bash

# create agent identities
planner = AgentIdentity.generate()
research = AgentIdentity.generate()

# create a packet
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
        allowed_actions=["read", "search", "summarize"],
        max_tool_calls=5
    ),
    signature_algo="Ed25519",
    signature="",
    public_key=planner.public_key_pem
)

# sign the packet
signed_packet = sign_packet(packet, planner)

# verify signature
verify_packet(signed_packet)

# process delegation
decision = process_handoff(signed_packet)

print(decision.decision)
print(decision.reason)

---

Expected output:

ACCEPT
Packet verified and valid

---

Core primitives

TrustHandoff revolves around four primitives:

SignedTaskPacket
DelegationEnvelope
DelegationChain
PacketDecision

These primitives allow verifiable delegation between AI agents.

---

Next steps

Explore:

examples/
adapters/
specs/

