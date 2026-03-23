[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/trusthandoff/trusthandoff/badge)](https://scorecard.dev/viewer/?uri=github.com/trusthandoff/trusthandoff)

[![PyPI version](https://img.shields.io/pypi/v/trusthandoff.svg)](https://pypi.org/project/trusthandoff/)

[![Python versions](https://img.shields.io/pypi/pyversions/trusthandoff.svg)](https://pypi.org/project/trusthandoff/)

[![License](https://img.shields.io/pypi/l/trusthandoff.svg)](https://github.com/trusthandoff/trusthandoff/blob/main/LICENSE)

[![Supply Chain](https://img.shields.io/badge/supply%20chain-Sigstore%20%2B%20SLSA-green)](https://github.com/trusthandoff/trusthandoff/actions)
Releases are published from GitHub Actions using Trusted Publishing and include verifiable build provenance / attestations.

## ⚔️ Attack Demo

<p align="center">
  <img src="demoattack_trusthandoff_gif" width="600"/>
</p>

> Legit output → accepted  
> Tampered output → rejected  
> Replay → rejected  

**Execution without proof is trust theater.**

# TrustHandoff

TrustHandoff is the **delegation and accountability layer for agent systems**.

It solves a critical blind spot:

Agents can act.  
Agents can delegate.  

But today:

→ no system proves what authority they had  
→ no system proves what actually happened  
→ no system makes them accountable  

TrustHandoff makes delegation **verifiable, enforceable, and auditable**.

## Why this exists

Modern agent frameworks solve:

- orchestration
- communication
- tool usage

They do NOT solve:

**verifiable delegation and agent accountability**

| Layer | What it solves | Example |
|---|---|---|
| Agent ↔ tools | tool/context access | MCP |
| Agent ↔ agent | communication | A2A |
| Agent orchestration | workflows | LangGraph / CrewAI / AutoGen |
| **Delegation + accountability** | **verifiable authority + execution trace** | **TrustHandoff** |

Without this layer, systems rely on implicit trust.

That leads to:

- silent privilege escalation
- replay attacks
- context poisoning
- unverifiable execution
- no accountability

## The shift

TrustHandoff turns agent actions into something:

- signed
- bounded
- traceable
- enforceable
- auditable

From:

trust the agent  

To:

**verify the delegation + prove the execution**

## Core primitive

SignedTaskPacket

A SignedTaskPacket allows one agent to hand off work to another while preserving:

- authority
- permissions
- provenance
- cryptographic integrity

## What TrustHandoff provides

- Ed25519 signed delegation
- bounded permissions
- multi-hop delegation chains
- nonce + timestamp replay protection
- revocation enforcement
- runtime policy enforcement
- audit hooks

Result:

**deterministic delegation pipeline**

## Security pipeline

Every packet goes through:

1. signature verification  
2. nonce replay protection  
3. timestamp validation  
4. delegation chain validation  
5. depth + scope enforcement  
6. revocation checks  
7. runtime policy enforcement  

No partial trust.  
Fail-fast validation.

## Runtime policy enforcement

TrustHandoff supports runtime policy hooks:

- deny specific actions
- restrict execution dynamically
- enforce environment rules

Strict mode:

TRUSTHANDOFF_STRICT_MODE=1

If no policy is provided, execution is rejected.

## Accountability (v0.3+)

TrustHandoff extends delegation into **agent accountability**.

Agents do not just receive authority — they must prove execution.

This includes:

- execution attestations
- signed outcomes
- verifiable result hashes
- audit trails

Each step in a delegation chain can produce a **cryptographic execution record**.

This enables:

- auditability  
- traceability  
- post-mortem analysis  
- compliance-ready logs  

From:

“the agent says it did it”  

To:

**the system proves it happened**

## Threat model

TrustHandoff reduces or blocks:

- impersonation  
- replay attacks  
- unbounded delegation  
- context poisoning  
- authority spoofing  

Out of scope:

- side-channel attacks  
- denial-of-service  
- physical key theft  

## Framework adapters

Supported:

- CrewAI  
- AutoGen  
- LangGraph  

Adapters map framework-native delegation into TrustHandoff primitives.

## Positioning

TrustHandoff is NOT:

- a transport layer  
- a message bus  
- an orchestration system  

It complements existing systems by adding:

- verifiable delegation  
- bounded authority  
- provenance-aware execution  
- auditability  

Recommended stack:

- MCP = tools  
- A2A = communication  
- LangGraph / CrewAI / AutoGen = orchestration  
- TrustHandoff = delegation + accountability  

## Quickstart

Minimal flow:

- create agents  
- create packet  
- sign packet  
- verify packet  
- process handoff  

Result:

ACCEPT → execution allowed  
REJECT → execution blocked  

## Contributing

We actively welcome contributors.

High leverage areas:

- adapters  
- attack simulations  
- security improvements  
- execution attestation  
- real-world integrations  

Setup:

git clone <repo>  
cd trusthandoff  
pip install -e .  
pytest  

Open a PR.

## Roadmap

v0.2

- protocol stabilization  
- delegation chain verification  
- middleware pipeline  
- adapters  

v0.3+

- execution attestation layer  
- verifiable completion proofs  
- execution receipts  
- optional TEE / zk attestation  

## License

MIT

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/trusthandoff)](https://pypi.org/project/trusthandoff/)
