from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    DelegationChain,
    DelegationEnvelope,
    Permissions,
    SignedTaskPacket,
    process_handoff,
    sign_packet,
)


def main():

    print("=== TrustHandoff Envelope Flow Demo ===")

    # Agent identities
    planner = AgentIdentity.generate()
    researcher = AgentIdentity.generate()

    # Planner creates packet
    packet = SignedTaskPacket(
        packet_id="pk_flow_001",
        task_id="task_flow_001",
        from_agent=planner.agent_id,
        to_agent=researcher.agent_id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-flow-001",
        intent="Research company background",
        context={"company": "Example Corp"},
        permissions=Permissions(
            allowed_actions=["read", "search", "summarize"],
            max_tool_calls=5,
        ),
        signature_algo="Ed25519",
        signature="",
        public_key=planner.public_key_pem,
    )

    # Sign packet
    packet = sign_packet(packet, planner)

    # Create delegation chain
    chain = DelegationChain(
        packet_ids=[packet.packet_id],
        agents=[planner.agent_id],
    )

    # Create envelope
    envelope = DelegationEnvelope(
        packet=packet,
        chain=chain,
    )

    # Process handoff
    decision = process_handoff(envelope.packet)

    print("Decision:", decision.decision)
    print("Reason:", decision.reason)

    # If accepted, extend the chain
    if decision.decision == "ACCEPT":
        envelope.chain.add_handoff(packet.packet_id, researcher.agent_id)

    print("Delegation depth:", envelope.chain.depth())
    print("Agents in chain:", envelope.chain.agents)


if __name__ == "__main__":
    main()
