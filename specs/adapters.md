# TrustHandoff Framework Adapters

## Purpose

This document describes how TrustHandoff adapters map framework-native delegation or handoff concepts to TrustHandoff protocol primitives.

TrustHandoff adapters do not replace framework runtimes.

They provide a trust-aware delegation layer on top of framework-native orchestration.

---

## Core positioning

Recommended framing:

- framework = orchestration / routing / messaging
- TrustHandoff = signed delegation / validation / chain / decision

TrustHandoff should be treated as a delegation trust layer, not a framework replacement.

---

## Current adapters

TrustHandoff currently provides v0.1 adapters for:

- CrewAI
- AutoGen
- LangGraph

These adapters are lightweight protocol integrations that map native framework delegation flows into:

- SignedTaskPacket
- DelegationEnvelope
- DelegationChain
- PacketDecision
- process_handoff()

---

## CrewAI mapping

CrewAI delegation concepts map to TrustHandoff as follows:

- CrewAI delegation event -> SignedTaskPacket
- delegating agent -> from_agent
- delegated target agent -> to_agent
- task intent -> intent
- task context -> context
- allowed actions -> permissions.allowed_actions

Flow:

CrewAI event
    -> create_packet(...)
    -> sign_packet(...)
    -> create_envelope(...)
    -> process_handoff(...)
    -> decision + envelope

---

## AutoGen mapping

AutoGen handoff concepts map to TrustHandoff as follows:

- AutoGen handoff event / swarm transfer -> SignedTaskPacket
- source agent -> from_agent
- target agent -> to_agent
- handoff intent -> intent
- task payload -> context

Flow:

AutoGen handoff
    -> create_packet(...)
    -> sign_packet(...)
    -> create_envelope(...)
    -> process_handoff(...)
    -> decision + envelope

---

## LangGraph mapping

LangGraph handoff / routing concepts map to TrustHandoff as follows:

- LangGraph state transition / handoff command -> SignedTaskPacket
- source node / agent -> from_agent
- target node / agent -> to_agent
- state intent -> intent
- graph state payload -> context

Flow:

LangGraph transition
    -> create_packet(...)
    -> sign_packet(...)
    -> create_envelope(...)
    -> process_handoff(...)
    -> decision + envelope

---

## Adapter contract summary

All adapters should support:

1. create_packet(...)
2. create_envelope(...)
3. process_framework_handoff(...)

Each adapter should:

- preserve TrustHandoff packet semantics
- preserve packet signature if enabled
- validate packet before acceptance
- extend DelegationChain when delegation continues
- respect permission narrowing when multi-hop delegation is introduced

---

## Scope of adapters v0.1

Current adapters are protocol-facing integrations.

They do not yet implement:

- async runtime integration
- framework plugin packaging
- live middleware hooks
- persistent replay protection
- loop detection
- chain verification
- automatic multi-hop policy enforcement

These remain future extensions.

---

## Goal

The goal of adapters is to make TrustHandoff usable inside major agent frameworks without requiring those frameworks to adopt a new runtime model.
