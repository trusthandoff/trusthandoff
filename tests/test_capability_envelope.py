from datetime import datetime, timezone

from trusthandoff import CapabilityTokenEnvelope


def test_capability_token_envelope_roundtrip():
    envelope = CapabilityTokenEnvelope(
        payload={"task": "search_docs"},
        capability_token="demo-token",
        nonce="nonce-123",
        issued_at=datetime.now(timezone.utc),
    )

    data = envelope.model_dump()
    restored = CapabilityTokenEnvelope(**data)

    assert restored.payload["task"] == "search_docs"
    assert restored.capability_token == "demo-token"
    assert restored.nonce == "nonce-123"
