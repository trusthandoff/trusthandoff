from datetime import datetime, timedelta, timezone

from trusthandoff.packet import SignedTaskPacket, Permissions


def test_signed_task_packet_accepts_capability_token():
    packet = SignedTaskPacket(
        packet_id="pkt-cap-1",
        task_id="task-cap-1",
        from_agent="agent:planner:alpha",
        to_agent="agent:research:beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        nonce="nonce-cap-1",
        capability_token="demo-capability-token",
        intent="delegate search task",
        permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key="demo-public-key",
    )

    assert packet.capability_token == "demo-capability-token"


def test_signed_task_packet_defaults_capability_token_to_none():
    packet = SignedTaskPacket(
        packet_id="pkt-cap-2",
        task_id="task-cap-2",
        from_agent="agent:planner:alpha",
        to_agent="agent:research:beta",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        nonce="nonce-cap-2",
        intent="delegate search task",
        permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key="demo-public-key",
    )

    assert packet.capability_token is None
