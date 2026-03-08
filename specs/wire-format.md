# TrustHandoff Wire Format

## Status

Working draft.

## Purpose

This document defines the canonical JSON wire format for TrustHandoff.

The wire format exists so that TrustHandoff packets and envelopes can move across:

- Python runtimes
- agent frameworks
- message buses
- HTTP transports
- future non-Python implementations

---

## Canonical transport object

The canonical transport object is:

DelegationEnvelope

A DelegationEnvelope contains:

- packet
- chain

---

## JSON format

TrustHandoff wire transport uses:

- JSON object encoding
- sorted keys for canonical serialization
- ISO8601 timestamps for datetime fields

---

## Envelope shape

A canonical TrustHandoff envelope MUST be encoded as a JSON object with this top-level structure:

- packet
- chain

Example:

```json
{
  "packet": {
    "packet_id": "pk_demo_001",
    "task_id": "task_demo_001",
    "from_agent": "agent:planner:alpha",
    "to_agent": "agent:research:beta",
    "issued_at": "2026-03-08T12:00:00+00:00",
    "expires_at": "2026-03-08T12:10:00+00:00",
    "nonce": "nonce-demo-001",
    "intent": "Research company background",
    "task_type": null,
    "goal": null,
    "context": {
      "company": "Example Corp"
    },
    "memory_refs": [],
    "permissions": {
      "allowed_actions": ["read", "search"],
      "max_tool_calls": 3
    },
    "constraints": null,
    "provenance": null,
    "signature_algo": "Ed25519",
    "signature": "demo-signature",
    "public_key": "demo-public-key"
  },
  "chain": {
    "packet_ids": ["pk_demo_001"],
    "agents": ["agent:planner:alpha"]
  }
}
```

## Datetime encoding

All datetime fields MUST be serialized as ISO8601 strings.

Current datetime fields include:

- issued_at  
- expires_at  

Example:

2026-03-08T12:00:00+00:00

## Canonicalization rules

Before signing or verification, TrustHandoff implementations should preserve deterministic encoding semantics.

Current canonicalization expectations:

- JSON object keys sorted consistently
- datetime values encoded as ISO8601 strings
- envelope structure preserved exactly as packet + chain

## Serialization helpers

Current reference implementation exposes:

- envelope_to_dict(envelope)
- envelope_from_dict(data)
- envelope_to_json(envelope)
- envelope_from_json(payload)

These helpers define the current reference wire behavior.

## Current limitations

The current wire format does not yet define:

- detached signatures
- binary encoding
- compression
- transport headers
- schema version negotiation
- multi-envelope batching

These may be added in future versions.

## Goal

The goal of the wire format is to make TrustHandoff portable, deterministic, and interoperable across agent runtimes.
