# TrustHandoff Adapter Contract v0.1

## Purpose

This document defines the minimum contract that any TrustHandoff framework adapter must implement.

TrustHandoff adapters are not full framework replacements.

They are thin integration layers that map native framework handoff/delegation concepts to TrustHandoff protocol primitives.

---

## Core rule

Framework communication remains owned by the framework.

TrustHandoff adds the delegation trust layer.

Recommended framing:

- framework = orchestration / routing / messaging
- TrustHandoff = signed delegation / validation / chain / decision

---

## Required adapter responsibilities

Every adapter must support these responsibilities:

1. Build a SignedTaskPacket from a framework-native handoff or delegation event
2. Optionally sign the packet using AgentIdentity
3. Wrap the packet in a DelegationEnvelope
4. Process the handoff using process_handoff()
5. Return a framework-compatible output
6. Preserve or extend DelegationChain when delegation continues

---

## Required mapping

Each adapter must define mappings for:

### Framework input
What native object or event triggers delegation?

Examples:
- CrewAI task delegation event
- AutoGen handoff tool call
- LangGraph state transition or handoff command

### Packet mapping
How framework delegation fields map to:

- packet_id
- task_id
- from_agent
- to_agent
- intent
- context
- permissions
- signature
- public_key

### Output mapping
How TrustHandoff output maps back into framework-native output.

Examples:
- framework task handoff object
- framework state update
- framework response or message

---

## Minimum adapter API

Each adapter should expose a minimal API with three functions:

### 1. create_packet(...)
Build a SignedTaskPacket from framework-native inputs.

### 2. create_envelope(...)
Wrap the packet in a DelegationEnvelope with an initial DelegationChain.

### 3. process_framework_handoff(...)
Execute TrustHandoff logic and return a framework-compatible output.

---

## Adapter output expectations

The adapter output should make it easy for the framework to consume:

- ACCEPT / REJECT decision
- reason
- packet
- envelope
- chain updates

---

## Security expectations

Every adapter must respect the TrustHandoff trust model:

- use SignedTaskPacket as canonical delegation object
- preserve packet signature if signing is enabled
- validate packets before accepting handoff
- preserve chain history
- enforce permission narrowing when delegation continues

---

## Current v0.1 scope

The first version of adapters may remain minimal.

Adapters do not need to implement:

- network transport
- framework plugin packaging
- async execution
- live middleware injection
- production persistence
- replay protection storage

They must implement the core delegation trust flow correctly.

---

## Canonical adapter flow

Framework event
    -> create_packet(...)
    -> sign_packet(...)
    -> create_envelope(...)
    -> process_handoff(...)
    -> framework-compatible result

If delegation continues:
    -> extend DelegationChain
    -> enforce permission narrowing

---

## Goal

The purpose of adapters is to let frameworks keep their native orchestration model while using TrustHandoff as the delegation trust layer.
