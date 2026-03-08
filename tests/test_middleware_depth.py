from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    DelegationChain,
    DelegationEnvelope,
    Permissions,
    SignedTaskPacket,
    TrustHandoffMiddleware,
    sign_packet,
)


def test_middleware_rejects_excessive_depth():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    packet = SignedTaskPacket(
        packet_id="pk_depth_001",
        task_id="task_depth_001",
        from_agent=planner.agent_id,
        to_agent=research.agent_id,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-depth-001",
        intent="Depth test",
        context={"company": "Example Corp"},
        permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        signature_algo="Ed25519",
        signature="",
        public_key=planner.public_key_pem,
    )

    signed_packet = sign_packet(packet, planner)

    # chain deeper than max_depth
    chain = DelegationChain(
        packet_ids=["pk1", "pk2", "pk3", "pk4", "pk5", "pk6"],
        agents=["a", "b", "c", "d", "e", "f"],
    )

    envelope = DelegationEnvelope(packet=signed_packet, chain=chain)

    middleware = TrustHandoffMiddleware(max_depth=5)

    decision = middleware.handle(envelope)

    assert decision.decision == "REJECT"
    assert decision.reason == "Delegation depth exceeded"
