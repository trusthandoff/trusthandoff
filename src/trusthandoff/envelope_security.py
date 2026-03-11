from datetime import datetime, timezone, timedelta

from .agent_registry import AgentRegistry
from .capability_envelope import CapabilityTokenEnvelope
from .capability_token import decode_capability_token
from .api import verify_capability_chain
from .replay import ReplayProtection


def verify_envelope_security(
    envelope: CapabilityTokenEnvelope,
    replay_protection: ReplayProtection,
    registry: AgentRegistry | None = None,
    max_age_seconds: int = 300,
) -> bool:
    """
    Verifies transport-level security for a capability token envelope.

    Checks:
    - nonce replay protection
    - issued_at freshness window
    - capability token decoding
    - capability trust validation
    """

    if not replay_protection.check_and_store(envelope.nonce):
        return False

    now = datetime.now(timezone.utc)
    age = now - envelope.issued_at

    if age < timedelta(seconds=0):
        return False

    if age > timedelta(seconds=max_age_seconds):
        return False

    capability = decode_capability_token(envelope.capability_token)

    return verify_capability_chain([capability], registry=registry)

def test_verify_envelope_security_rejects_expired_envelope():
    identity = AgentIdentity.generate()

    registry = AgentRegistry()
    registry.register(identity.agent_id, identity.public_key_pem)

    capability = DelegationCapability(
        capability_id="cap-env-2",
        issuer_agent=identity.agent_id,
        subject_agent="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read"],
            max_tool_calls=1,
        ),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature_algo="Ed25519",
        signature="",
        public_key=identity.public_key_pem,
    )
    capability = sign_capability(capability, identity.private_key_pem)
    token = encode_capability_token(capability)

    envelope = CapabilityTokenEnvelope(
        payload={"task": "search_docs"},
        capability_token=token,
        nonce="nonce-env-expired",
        issued_at=datetime.now(timezone.utc) - timedelta(minutes=10),
    )

    replay = ReplayProtection()

    assert verify_envelope_security(
        envelope,
        replay,
        registry=registry,
        max_age_seconds=300,
    ) is False
