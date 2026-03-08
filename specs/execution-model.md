# TrustHandoff Execution Model

## Status

Working draft.

## Purpose

This document defines the canonical execution pipeline for processing a TrustHandoff delegation.

It describes how a receiving agent runtime should process a DelegationEnvelope before executing a delegated task.

The execution model ensures that delegated actions are verified, bounded, and safe before execution.

---

# Execution Pipeline

A TrustHandoff envelope MUST pass the following pipeline before task execution.

receive envelope  
→ verify signature  
→ validate packet  
→ replay protection  
→ delegation chain validation  
→ policy checks  
→ delegation decision  
→ execution gate  
→ task execution

Any failure in the pipeline MUST result in packet rejection.

---

# Step 1 — Receive DelegationEnvelope

The runtime receives a DelegationEnvelope.

Structure:

DelegationEnvelope  
- packet : SignedTaskPacket  
- chain : DelegationChain  

The envelope contains both the task and the delegation provenance.

---

# Step 2 — Signature Verification

The runtime MUST verify the packet signature.

verify_packet(packet)

Verification checks:

- signature matches packet payload
- public key corresponds to the signing identity
- signature algorithm is supported

Failure result:

REJECT  
reason: "Invalid signature"

---

# Step 3 — Packet Validation

The runtime MUST validate packet temporal validity.

validate_packet(packet)

Validation checks:

- issued_at <= expires_at
- expires_at > current_time

Failure result:

REJECT  
reason: "Packet validation failed"

---

# Step 4 — Replay Protection

The runtime SHOULD verify that the packet nonce has not been seen before.

Replay protection prevents reusing the same packet multiple times.

Typical implementation:

nonce_store.contains(packet.nonce)

If nonce already exists:

REJECT  
reason: "Replay detected"

---

# Step 5 — Delegation Chain Validation

The runtime MUST validate the delegation chain.

Checks include:

- chain length ≤ max_delegation_depth
- no agent loop in chain
- chain packet_ids consistency

Failure result:

REJECT  
reason: "Invalid delegation chain"

---

# Step 6 — Policy Checks

The runtime MUST verify policy constraints.

Example checks:

permissions_child ⊆ permissions_parent

Child delegations cannot expand authority beyond their parent.

Other possible checks:

- data boundary constraints
- runtime limits
- tool restrictions

Failure result:

REJECT  
reason: "Delegation policy violation"

---

# Step 7 — Delegation Decision

If all checks pass, the runtime produces a PacketDecision.

PacketDecision contains:

- packet_id
- decision
- reason

Possible values:

ACCEPT  
REJECT

---

# Step 8 — Execution Gate

If the decision is ACCEPT, the envelope may pass through the execution gate.

The execution gate controls whether the delegated task is allowed to run.

Example implementation:

TrustHandoffExecutor

Responsibilities:

- enforce runtime policies
- enforce delegation depth
- ensure callable execution is safe

---

# Step 9 — Task Execution

If execution is authorized, the runtime may execute the delegated callable.

Example:

decision, result = executor.execute(envelope, task_callable)

If rejected:

result = None

---

# Design Principle

TrustHandoff separates:

transport  
delegation verification  
policy enforcement  
execution

This separation allows TrustHandoff to remain independent of specific agent runtimes or frameworks.

---

# Compatibility

The execution model is framework-agnostic.

It can be implemented in:

- LangGraph runtimes
- CrewAI runtimes
- AutoGen runtimes
- custom agent frameworks

TrustHandoff defines the trust layer, not the orchestration layer.
