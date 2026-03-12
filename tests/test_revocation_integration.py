from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    AgentRegistry,
    CapabilityRevocationRegistry,
    DelegationCapability,
    verify_capability_chain,
)
from trusthandoff.packet import Permissions


def test_verify_capability_chain_rejects_revoked_capability():

    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    registry = AgentRegistry()
    registry.register(planner.agent_id, planner.public_key_pem)
    registry.register(research.agent_id, research.public_key_pem)

    revocation = CapabilityRevocationRegistry()

    cap = DelegationCapability(
        capability_id="cap-revoked",
        issuer_agent=planner.agent_id,
        subject_agent=research.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["read"],
            max_tool_calls=1,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="sig",
        public_key=planner.public_key_pem,
    )

    revocation.revoke("cap-revoked")

    assert verify_capability_chain(
        [cap],
        registry=registry,
        revocation_registry=revocation,
    ) is False
