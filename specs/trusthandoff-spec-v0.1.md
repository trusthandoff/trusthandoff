# TrustHandoff Spec v0.1

## Status

Working draft.

## Purpose

TrustHandoff standardizes verifiable task delegation between AI agents.

It does not replace:
- MCP for agent-to-tool/context interactions
- A2A for agent-to-agent communication

It adds the missing trust layer for:
- secure delegation
- bounded execution
- verifiable origin
- packet-level validation

---

## Core primitive

The atomic unit of TrustHandoff is:

SignedTaskPacket

A SignedTaskPacket is the minimum portable object required for one agent to delegate a task to another agent in a verifiable way.

---

## SignedTaskPacket fields

### Identity and routing
- packet_id
- task_id
- from_agent
- to_agent

### Time / replay protection
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

### Constraints
- permissions
- constraints
- provenance

### Signature
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

## Agent identity

TrustHandoff defines AgentIdentity.

AgentIdentity provides:
- agent_id
- private_key_pem
- public_key_pem

The current identity model uses:
- Ed25519 keypairs
- SHA-256 hash of public key to derive agent_id

Format:

agent:<short-hash>

---

## Current primitives

### Implemented
- SignedTaskPacket
- AgentIdentity
- sign_packet(packet, identity)
- verify_packet(packet)
- validate_packet(packet)

### Not yet implemented
- packet decision helpers
- revocation
- replay protection storage
- policy engine
- trust registry
- framework adapters

---

## Packet lifecycle

1. Sender creates SignedTaskPacket
2. Sender signs packet with sign_packet()
3. Packet is transmitted
4. Receiver verifies signature with verify_packet()
5. Receiver validates time bounds with validate_packet()
6. Receiver decides to accept or reject

---

## Validation rules in v0.1

Current validate_packet() checks:
- issued_at must not be after expires_at
- packet must not already be expired

---

## Cryptographic rules in v0.1

Current sign_packet() uses:
- Ed25519 private key
- payload based on packet content excluding signature

Current verify_packet() uses:
- public key included in packet
- Ed25519 verification

---

## Design principles

- Minimalism
- Portability
- Verifiability
- Bounded authority
- Layerability
- Auditability

---

## Canonical statement

TrustHandoff standardizes verifiable task delegation between AI agents through a SignedTaskPacket carrying identity, intent, context, permissions, constraints, provenance, and cryptographic proof.
