from datetime import datetime, timedelta, timezone

from trusthandoff.packet import SignedTaskPacket, Permissions
from trusthandoff.capability_extraction import extract_capability_token


def test_extract_capability_token_present():
    packet = SignedTaskPacket(
        packet_id="pkt-1",
        task_id="task-1",
        from_agent="agent:a",
        to_agent="agent:b",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        nonce="nonce-1",
        capability_token="cap-123",
        intent="run task",
        permissions=Permissions(
            allowed_actions=["run"]
        ),
        signature_algo="Ed25519",
        signature="sig",
        public_key="pk",
    )

    assert extract_capability_token(packet) == "cap-123"

def test_extract_capability_token_missing():
    packet = SignedTaskPacket(
        packet_id="pkt-2",
        task_id="task-2",
        from_agent="agent:a",
        to_agent="agent:b",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        nonce="nonce-2",
        intent="run task",
        permissions=Permissions(
            allowed_actions=["run"]
        ),
        signature_algo="Ed25519",
        signature="sig",
        public_key="pk",
    )

    assert extract_capability_token(packet) is None
