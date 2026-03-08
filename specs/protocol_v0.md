TrustHandoff Protocol v0

Overview
-------
TrustHandoff defines a cryptographically verifiable delegation packet for autonomous agents.

TrustHandoff is a delegation trust layer for autonomous agents.

It is not a transport protocol, message bus, or orchestration framework.

Its role is to provide verifiable delegation, bounded authority, and portable provenance across agent runtimes.

Core Objects
------------

SignedTaskPacket
DelegationChain
DelegationEnvelope

SignedTaskPacket Fields
-----------------------

packet_id
task_id
from_agent
to_agent
issued_at
expires_at
nonce
intent
context
permissions
signature_algo
signature
public_key

DelegationChain
---------------

packet_ids
agents

DelegationEnvelope
------------------

packet
chain

Security Guarantees
-------------------

Prevents impersonation
Prevents replay attacks
Prevents unbounded delegation
Provides full provenance chain

Wire Format
-----------

JSON canonical format
sorted keys
ISO8601 timestamps

Example Payload
---------------

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
    "context": {
      "company": "Example Corp"
    },
    "permissions": {
      "allowed_actions": ["read", "search"],
      "max_tool_calls": 3
    },
    "signature_algo": "Ed25519",
    "signature": "demo-signature",
    "public_key": "demo-public-key"
  },
  "chain": {
    "packet_ids": ["pk_demo_001"],
    "agents": ["agent:planner:alpha"]
  }
}

This payload represents the canonical JSON wire format for a TrustHandoff DelegationEnvelope.
