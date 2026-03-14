from datetime import datetime, timedelta, timezone

from trusthandoff import AgentIdentity, AgentRegistry, sign_capability
from trusthandoff.capability import DelegationCapability
from trusthandoff.execution_control import execute_authorized_action
from trusthandoff.packet import Permissions
from trusthandoff.policy import deny_file_write_policy


def test_runtime_policy_denies_file_write():
    planner = AgentIdentity.generate()
    worker = AgentIdentity.generate()

    registry = AgentRegistry()
    registry.register(planner.agent_id, planner.public_key_pem)
    registry.register(worker.agent_id, worker.public_key_pem)

    cap = DelegationCapability(
        capability_id="cap-policy-1",
        issuer_agent=planner.agent_id,
        subject_agent=worker.agent_id,
        delegated_permissions=Permissions(
            allowed_actions=["file_write"],
            max_tool_calls=1,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="",
        public_key=planner.public_key_pem,
    )

    cap = sign_capability(cap, planner.private_key_pem)

    ok, result = execute_authorized_action(
        [cap],
        action="file_write",
        fn=lambda: "should not run",
        registry=registry,
        tool_calls_used=0,
        policy=deny_file_write_policy,
    )

    assert ok is False
    assert result == "policy_denied:file_write"
