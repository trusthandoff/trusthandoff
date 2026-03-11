from datetime import datetime, timedelta, timezone

from trusthandoff import (
    AgentIdentity,
    AgentRegistry,
    DelegationCapability,
    sign_capability,
    verify_capability_chain,
)
from trusthandoff.packet import Permissions


def test_verify_capability_chain_accepts_valid_registered_chain():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()
    analyst = AgentIdentity.generate()

    registry = AgentRegistry()
    registry.register(planner.agent_id, planner.public_key_pem)
    registry.register(research.agent_id, research.public_key_pem)
    registry.register(analyst.agent_id, analyst.public_key_pem)

    cap1 = DelegationCapability(
        capability_id="cap-1",
        issuer_agent=planner.agent_id,
        subject_agent=research.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=5,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=3),
        signature_algo="Ed25519",
        signature="",
        public_key=planner.public_key_pem,
    )
    cap1 = sign_capability(cap1, planner.private_key_pem)

    cap2 = DelegationCapability(
        capability_id="cap-2",
        issuer_agent=research.agent_id,
        subject_agent=analyst.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=3,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        parent_capability_id="cap-1",
        signature_algo="Ed25519",
        signature="",
        public_key=research.public_key_pem,
    )
    cap2 = sign_capability(cap2, research.private_key_pem)

    assert verify_capability_chain([cap1, cap2], registry=registry) is True


def test_verify_capability_chain_rejects_unknown_issuer():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()

    registry = AgentRegistry()
    registry.register(planner.agent_id, planner.public_key_pem)

    cap1 = DelegationCapability(
        capability_id="cap-1",
        issuer_agent=planner.agent_id,
        subject_agent=research.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        signature_algo="Ed25519",
        signature="",
        public_key=planner.public_key_pem,
    )
    cap1 = sign_capability(cap1, planner.private_key_pem)

    cap2 = DelegationCapability(
        capability_id="cap-2",
        issuer_agent=research.agent_id,
        subject_agent="agent:analyst:gamma",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=1,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        parent_capability_id="cap-1",
        signature_algo="Ed25519",
        signature="",
        public_key=research.public_key_pem,
    )
    cap2 = sign_capability(cap2, research.private_key_pem)

    assert verify_capability_chain([cap1, cap2], registry=registry) is False


def test_verify_capability_chain_rejects_invalid_signature():
    planner = AgentIdentity.generate()
    research = AgentIdentity.generate()
    analyst = AgentIdentity.generate()

    registry = AgentRegistry()
    registry.register(planner.agent_id, planner.public_key_pem)
    registry.register(research.agent_id, research.public_key_pem)
    registry.register(analyst.agent_id, analyst.public_key_pem)

    cap1 = DelegationCapability(
        capability_id="cap-1",
        issuer_agent=planner.agent_id,
        subject_agent=research.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=5,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=3),
        signature_algo="Ed25519",
        signature="",
        public_key=planner.public_key_pem,
    )
    cap1 = sign_capability(cap1, planner.private_key_pem)

    cap2 = DelegationCapability(
        capability_id="cap-2",
        issuer_agent=research.agent_id,
        subject_agent=analyst.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        parent_capability_id="cap-1",
        signature_algo="Ed25519",
        signature="",
        public_key=research.public_key_pem,
    )
    cap2 = sign_capability(cap2, research.private_key_pem)

    cap2.subject_agent = "agent:attacker:omega"

    assert verify_capability_chain([cap1, cap2], registry=registry) is False
