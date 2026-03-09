# TrustHandoff Protocol — Identity Model

## Problem

The TrustHandoff protocol verifies packet signatures to ensure message integrity.

However, signature verification alone does not prove that the public key used to sign the packet actually belongs to the agent identified in the packet.

Example:

packet.from_agent = "agent:planner:alpha"

signature = valid
public_key = attacker_key

If the protocol only checks that the signature matches the provided public key, an attacker could impersonate another agent by including a different key.

Therefore the protocol must bind:

agent_id ↔ public_key

This is known as **identity binding**.

## Identity Binding Rule

For every packet:

packet.from_agent must resolve to a trusted public key.

The public key used to verify the packet signature must match the registered key for that agent.

Validation rule:

registry_key = AgentRegistry.resolve(packet.from_agent)

if registry_key != packet.public_key:
    REJECT

If the keys match, the packet signature verification proceeds normally.

## Agent Identifier Format

Agent identifiers follow a simple namespace structure:

agent:<role>:<instance>

Examples:

agent:planner:alpha
agent:research:beta
agent:executor:gamma

The format is intentionally simple and transport-agnostic.

TrustHandoff does not enforce a global identity system, but defines how identities map to keys.

## Agent Registry

The protocol introduces the concept of an Agent Registry.

The registry provides the mapping:

agent_id → public_key

The registry can be implemented in multiple ways:

Local registry

known_agents.json

Example:

{
  "agent:planner:alpha": "-----BEGIN PUBLIC KEY-----...",
  "agent:research:beta": "-----BEGIN PUBLIC KEY-----..."
}

DNS-based identity

agent:planner:alpha → planner.alpha.domain → public key

DID-based identity

did:agent:planner:alpha → DID document → public key

Remote registry service

GET /agents/{agent_id}/public_key

The TrustHandoff protocol does not mandate a single registry mechanism.

Instead, it defines the resolution rule.

## Verification Pipeline Integration

Identity verification occurs before packet signature verification.

Updated verification order:

1. Resolve agent identity

registry_key = AgentRegistry.resolve(packet.from_agent)

2. Verify key match

registry_key == packet.public_key

3. Verify packet signature

verify(signature, registry_key)

4. Continue verification pipeline

- replay protection
- expiration
- delegation chain validation
- authority propagation checks

## Security Properties

Identity binding guarantees:

- agents cannot impersonate other agents
- packets cannot introduce arbitrary public keys
- delegation chains remain cryptographically attributable

Combined with packet signatures and authority propagation rules, this provides:

- verifiable delegation
- bounded authority
- tamper-resistant agent interactions

## Future Extensions

Future protocol versions may support:

- key rotation
- multi-key agents
- certificate chains
- DID integration
- federated trust registries

These extensions remain compatible with the core rule:

agent identity must resolve to a trusted public key before packet verification.
