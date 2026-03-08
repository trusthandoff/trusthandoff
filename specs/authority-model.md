# TrustHandoff Protocol — Authority Propagation Model

## Problem

In multi-agent systems, tasks are frequently delegated across several agents:

A → B → C → D

Without strict authority propagation control, permissions can silently expand across delegation hops.

Example:

A grants B:

allowed_actions = ["search"]

B delegates to C:

allowed_actions = ["search", "read"]

C delegates to D:

allowed_actions = ["search", "read", "write"]

This results in a privilege escalation where the final agent (D) can perform actions never authorized by the original agent (A).

This class of vulnerability is known as **authority amplification** or **delegation escalation**.

The TrustHandoff protocol prevents this by enforcing strict permission propagation rules.

## Core Rule

For every delegation hop:

child_permissions ⊆ parent_permissions

Meaning:

The delegated permissions must always be a subset of the permissions received.

No agent in the delegation chain may increase authority.

## Permission Components

Current permission structure:

Permissions:
- allowed_actions: List[str]
- max_tool_calls: Optional[int]

Rules:

1. allowed_actions must be a subset
2. max_tool_calls cannot increase
3. constraints cannot be relaxed
4. runtime limits cannot increase

Example valid delegation:

Parent:
allowed_actions = ["read", "search"]
max_tool_calls = 3

Child:
allowed_actions = ["search"]
max_tool_calls = 2

Example invalid delegation:

Parent:
allowed_actions = ["search"]

Child:
allowed_actions = ["search", "write"]

Result: REJECT

## Current Protocol Limitation

The current DelegationChain model only tracks:

packet_ids
agents

It does not yet store the permissions granted at each hop.

Therefore, full multi-hop authority verification cannot yet be enforced purely from the chain structure.

The protocol currently relies on:

- packet signature validation
- replay protection
- delegation depth limits
- policy checks

Authority propagation validation is implemented as a primitive:

delegation_scope_check(parent_permissions, child_permissions)

However, the chain does not yet store per-hop permissions.

## Future Extension: DelegationHop Model

To support full multi-hop verification, the protocol will introduce a DelegationHop structure.

DelegationHop:

agent_id
delegated_permissions
timestamp
signature

DelegationChain will evolve to:

DelegationChain:
hops: List[DelegationHop]

This allows verification across the entire chain:

hop1_permissions
∩ hop2_permissions
∩ hop3_permissions
...

Ensuring the final agent never receives permissions exceeding the original grant.

## Security Property

The TrustHandoff protocol enforces **monotonic authority reduction**.

Authority may only decrease across delegation hops.

This ensures:

- no privilege escalation
- no hidden capability amplification
- deterministic permission boundaries

## Implementation Layer

Authority validation occurs in the verification pipeline:

verify_envelope()

Pipeline stages:

1. verify_packet_signature
2. validate_packet_structure
3. replay_protection
4. chain_validation
5. delegation_scope_check
6. policy_checks
7. decision

## Design Goal

The authority propagation model ensures that:

The first agent in the chain defines the maximum authority envelope.

All subsequent delegations operate strictly within that envelope.

This makes TrustHandoff compatible with capability-based security models such as:

- AWS IAM delegation constraints
- Google Zanzibar authorization model
- capability-secure distributed systems

