# TrustHandoff Protocol — Capability Delegation Model

## Problem

In a message-based delegation system, authority is carried implicitly inside packets.

Example:

A → B : packet with permissions
B → C : packet with permissions
C → D : packet with permissions

This approach works for basic delegation, but it has structural weaknesses:

- authority is re-described at each hop
- provenance can become fragmented
- delegation semantics depend on message structure
- authority is not represented as a portable cryptographic object

To support robust multi-agent delegation across runtimes and frameworks, TrustHandoff introduces the concept of a capability.

A capability is a portable, verifiable delegation object that represents bounded authority.

## Core Definition

A capability is a cryptographically verifiable object that grants an agent a limited set of permissions under explicit constraints.

A capability must define:

- issuer
- subject
- granted permissions
- constraints
- expiration
- parent capability reference
- signature

This makes authority portable across:

- processes
- runtimes
- frameworks
- transports

## Capability Chain

Delegation no longer depends only on message passing.

Instead, delegation becomes a capability derivation chain.

Example:

A issues capability C1 to B
B derives capability C2 to C
C derives capability C3 to D

Rules:

- each derived capability must be a subset of its parent
- no derived capability may expand authority
- each capability must preserve provenance to its parent

This creates a chain of authority that is cryptographically attributable.

## Capability Structure

Proposed capability structure:

DelegationCapability

Fields:

- capability_id: str
- issuer_agent: str
- subject_agent: str
- delegated_permissions: Permissions
- constraints: Optional[Constraints]
- issued_at: datetime
- expires_at: datetime
- parent_capability_id: Optional[str]
- signature_algo: str
- signature: str
- public_key: str

Meaning:

capability_id
Unique identifier for the capability.

issuer_agent
The agent that issued the capability.

subject_agent
The agent receiving the capability.

delegated_permissions
The bounded authority granted.

constraints
Execution or policy limits associated with the capability.

issued_at / expires_at
Validity window.

parent_capability_id
Reference to the capability from which this one was derived.

signature
Cryptographic attestation by the issuer.

public_key
Issuer key used for verification.

## Core Security Rule

For every derived capability:

child_capability.permissions ⊆ parent_capability.permissions

and

child_capability.constraints must not be weaker than parent_capability.constraints

This enforces monotonic authority reduction.

Authority may only decrease.

## Capability Verification

Capability verification includes:

1. issuer identity binding
2. signature verification
3. expiration check
4. parent reference validation
5. subset validation against parent capability
6. policy validation

Verification must ensure that the subject of a parent capability is the issuer of the derived capability.

Example:

C1: issuer=A, subject=B
C2: issuer=B, subject=C

Valid

But:

C1: issuer=A, subject=B
C2: issuer=X, subject=C

Invalid

## Relationship to Existing TrustHandoff Objects

Current TrustHandoff objects:

- SignedTaskPacket
- DelegationEnvelope
- DelegationChain
- DelegationHop

Capabilities do not replace these objects immediately.

Instead:

- packets carry tasks
- envelopes carry packets plus chain metadata
- capabilities carry portable authority

Future model:

packet execution may reference a capability_id

This allows task delegation to be cleanly separated from authority delegation.

Task = what should be done
Capability = what may be done

## Design Goal

The capability model makes TrustHandoff suitable for:

- portable delegation across frameworks
- offline delegation validation
- cross-runtime trust enforcement
- deterministic authority propagation
- capability-secure multi-agent systems

This moves TrustHandoff from a packet verification protocol toward a true delegation authority layer.

## Example Delegation Flow

1. agent:planner:alpha issues capability C1 to agent:research:beta
2. C1 grants:
   allowed_actions = ["read", "search"]
   max_tool_calls = 5

3. agent:research:beta derives capability C2 to agent:analyst:gamma
4. C2 grants:
   allowed_actions = ["search"]
   max_tool_calls = 2

5. Validation checks:
   - issuer identity binding
   - parent-child relationship
   - monotonic reduction of authority
   - valid signatures at each hop

Result:

C2 is valid because it is narrower than C1.

## Future Extensions

Future protocol versions may support:

- capability revocation
- capability rotation
- capability attenuation proofs
- capability storage backends
- capability token serialization in wire format
- signed multi-hop capability chains

## Strategic Positioning

TrustHandoff does not compete with orchestration frameworks or transport protocols.

Capabilities position TrustHandoff as the delegation trust layer that can operate across:

- A2A transports
- orchestration frameworks
- tool execution runtimes
- agent coordination protocols

This makes TrustHandoff a candidate authority layer for the agent ecosystem.
