from datetime import datetime, timedelta, timezone

from trusthandoff import (
    DelegationCapability,
    encode_capability_token,
    decode_capability_token,
)
from trusthandoff.packet import Permissions


def test_capability_token_roundtrip():
    capability = DelegationCapability(
        capability_id="cap-token-1",
        issuer_agent="agent:planner:alpha",
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        parent_capability_id=None,
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key="demo-public-key",
    )

    token = encode_capability_token(capability)
    decoded = decode_capability_token(token)

    assert isinstance(token, str)
    assert decoded.capability_id == capability.capability_id
    assert decoded.issuer_agent == capability.issuer_agent
    assert decoded.subject_agent == capability.subject_agent
    assert decoded.delegated_permissions.allowed_actions == ["read", "search"]
    assert decoded.delegated_permissions.max_tool_calls == 3
    assert decoded.signature == "demo-signature"
    assert decoded.public_key == "demo-public-key"
