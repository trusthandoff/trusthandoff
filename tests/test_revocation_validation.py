from datetime import datetime, timedelta, timezone

from trusthandoff import (
    CapabilityRevocationRegistry,
    DelegationCapability,
    is_chain_revoked,
)
from trusthandoff.packet import Permissions


def test_is_chain_revoked_returns_true_if_parent_revoked():
    registry = CapabilityRevocationRegistry()

    cap1 = DelegationCapability(
        capability_id="cap-parent",
        issuer_agent="agent:planner:alpha",
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=5,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=3),
        signature_algo="Ed25519",
        signature="sig1",
        public_key="key1",
    )

    cap2 = DelegationCapability(
        capability_id="cap-child",
        issuer_agent="agent:research:beta",
        subject_agent="agent:analyst:gamma",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
        parent_capability_id="cap-parent",
        signature_algo="Ed25519",
        signature="sig2",
        public_key="key2",
    )

    registry.revoke("cap-parent")

    assert is_chain_revoked([cap1, cap2], registry) is True


def test_is_chain_revoked_returns_false_when_no_capability_revoked():
    registry = CapabilityRevocationRegistry()

    cap1 = DelegationCapability(
        capability_id="cap-parent",
        issuer_agent="agent:planner:alpha",
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read"],
            max_tool_calls=1,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="sig1",
        public_key="key1",
    )

    cap2 = DelegationCapability(
        capability_id="cap-child",
        issuer_agent="agent:research:beta",
        subject_agent="agent:analyst:gamma",
        delegated_permissions=Permissions(
            allowed_actions=["read"],
            max_tool_calls=1,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        parent_capability_id="cap-parent",
        signature_algo="Ed25519",
        signature="sig2",
        public_key="key2",
    )

    assert is_chain_revoked([cap1, cap2], registry) is False
