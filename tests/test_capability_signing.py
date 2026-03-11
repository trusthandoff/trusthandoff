from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    DelegationCapability,
    sign_capability,
    verify_capability_signature,
)
from trusthandoff.packet import Permissions


def test_sign_and_verify_capability_signature():
    identity = AgentIdentity.generate()

    capability = DelegationCapability(
        capability_id="cap-sign-1",
        issuer_agent=identity.agent_id,
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="",
        public_key=identity.public_key_pem,
    )

    signed = sign_capability(capability, identity.private_key_pem)

    assert signed.signature != ""
    assert verify_capability_signature(signed) is True


def test_capability_signature_fails_after_tampering():
    identity = AgentIdentity.generate()

    capability = DelegationCapability(
        capability_id="cap-sign-2",
        issuer_agent=identity.agent_id,
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read"],
            max_tool_calls=2,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="",
        public_key=identity.public_key_pem,
    )

    signed = sign_capability(capability, identity.private_key_pem)

    signed.subject_agent = "agent:attacker:omega"

    assert verify_capability_signature(signed) is False
