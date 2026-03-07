from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    Permissions,
    SignedTaskPacket,
    process_handoff,
    sign_packet,
)


def test_process_handoff_accepts_valid_packet():
    identity = AgentIdentity.generate()

    packet = SignedTaskPacket(
        packet_id="pk_handoff_001",
        task_id="task_handoff_001",
        from_agent=identity.agent_id,
        to_agent="agent:research:beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="nonce-handoff-001",
        intent="Process this handoff",
        context={"company": "Example Corp"},
        permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        signature_algo="Ed25519",
        signature="",
        public_key=identity.public_key_pem,
    )

    signed_packet = sign_packet(packet, identity)
    decision = process_handoff(signed_packet)

    assert decision.packet_id == signed_packet.packet_id
    assert decision.decision == "ACCEPT"
    assert decision.reason == "Packet verified and valid"
