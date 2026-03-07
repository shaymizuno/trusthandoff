# TrustHandoff Protocol Spec v0.2

## Status

Working draft.

## Positioning

TrustHandoff is a trust layer for verifiable task delegation between AI agents.

It is not a replacement for:

- MCP, which focuses on agent-to-tool and context interactions
- A2A, which focuses on agent-to-agent communication and discovery

TrustHandoff complements these systems by standardizing the delegation trust layer:

- signed task delegation
- packet verification
- packet validation
- decisioning
- canonical handoff processing
- portable packet serialization

---

## Purpose

TrustHandoff standardizes how one agent can delegate a task to another agent in a verifiable and bounded way.

The protocol defines:

- a canonical packet format
- a cryptographic identity model
- packet signing rules
- packet verification rules
- packet validation rules
- a canonical decision model
- a canonical handoff processing flow
- portable serialization helpers

---

## Atomic unit

The atomic unit of TrustHandoff is:

SignedTaskPacket

A SignedTaskPacket is the minimum portable object required for one agent to delegate a task to another agent in a verifiable way.

---

## Core primitives in v0.2

TrustHandoff v0.2 includes:

- SignedTaskPacket
- AgentIdentity
- sign_packet(packet, identity)
- verify_packet(packet)
- validate_packet(packet)
- PacketDecision
- process_handoff(packet)
- packet_to_dict(packet)
- packet_from_dict(data)

---

## SignedTaskPacket format

### Identity and routing
- packet_id
- task_id
- from_agent
- to_agent

### Time and replay-related fields
- issued_at
- expires_at
- nonce

### Task semantics
- intent
- task_type
- goal

### Context
- context
- memory_refs

### Execution controls
- permissions
- constraints
- provenance

### Signature material
- signature_algo
- signature
- public_key

---

## Sub-models

### Permissions
- allowed_actions
- max_tool_calls

### Constraints
- max_runtime_seconds
- data_boundary

### Provenance
- origin_workflow
- delegation_depth

---

## Agent identity model

TrustHandoff defines AgentIdentity.

AgentIdentity currently includes:

- agent_id
- private_key_pem
- public_key_pem

Current generation model:

1. Generate Ed25519 keypair
2. Derive public key
3. Hash public key with SHA-256
4. Derive short agent_id

Format:

agent:<short-hash>

---

## Signing rules

sign_packet(packet, identity) performs the following:

1. Load Ed25519 private key from identity
2. Serialize packet content excluding the signature field
3. Sign the serialized packet payload
4. Base64-encode the signature
5. Return a copy of the packet with the signature populated

Current v0.2 rule:

- signature field is excluded from the signing payload
- packet public_key is expected to carry the public verification material

---

## Verification rules

verify_packet(packet) performs the following:

1. Load public key from packet.public_key
2. Serialize packet content excluding the signature field
3. Decode packet.signature from base64
4. Verify Ed25519 signature against the payload
5. Return True if valid, False if invalid

Current v0.2 rule:

- invalid signature returns False
- public key must be Ed25519-compatible

---

## Validation rules

validate_packet(packet) performs the following checks:

1. issued_at must not be after expires_at
2. expires_at must not already be in the past

Current v0.2 scope:

- temporal validity only
- no replay storage yet
- no policy engine yet

---

## Decision model

PacketDecision currently contains:

- packet_id
- decision
- reason

Allowed decision values in v0.2:

- ACCEPT
- REJECT

This object is intended to represent the canonical response to a handoff packet.

---

## Canonical handoff flow

process_handoff(packet) performs the following:

1. verify_packet(packet)
2. validate_packet(packet)
3. return PacketDecision

Decision logic in v0.2:

- invalid signature => REJECT / "Invalid signature"
- failed validation => REJECT / "Packet validation failed"
- valid packet => ACCEPT / "Packet verified and valid"

---

## Serialization model

TrustHandoff includes:

- packet_to_dict(packet)
- packet_from_dict(data)

Purpose:

- allow packet transport outside the local Python object model
- support future interoperability across runtimes and frameworks
- make SignedTaskPacket portable

---

## Current guarantees

TrustHandoff v0.2 currently guarantees:

- canonical packet shape
- identity generation
- packet signing
- packet verification
- temporal validation
- canonical handoff decision flow
- packet serialization / deserialization

---

## Current non-goals

TrustHandoff v0.2 does not yet define:

- delegation chains
- replay protection storage
- revocation
- policy engine
- trust registry
- capability narrowing across multiple handoffs
- network transport
- discovery
- framework adapters

---

## Design principles

- Minimalism
- Portability
- Verifiability
- Bounded authority
- Auditability
- Layerability

---

## Ecosystem role

TrustHandoff should be positioned as:

- a delegation trust layer
- a protocol-compatible packet and trust model
- a complement to A2A and MCP

Recommended framing:

A2A handles communication.
TrustHandoff handles trusted delegation.

---

## Canonical statement

TrustHandoff standardizes verifiable task delegation between AI agents through a SignedTaskPacket carrying identity, intent, context, permissions, constraints, provenance, and cryptographic proof, along with canonical signing, verification, validation, decision, handoff, and serialization flows.
