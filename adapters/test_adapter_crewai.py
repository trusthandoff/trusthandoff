import pytest

from adapters.adapter_crewai import TrustHandoffCrewAIAdapter


class MockIdentity:
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.agent_id = "agent-test"

        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


def test_crewai_success():
    identity = MockIdentity()
    adapter = TrustHandoffCrewAIAdapter(identity)

    def task(inputs):
        return {"value": 42}

    wrapped = adapter.wrap_task(task)

    output = wrapped({"packet_id": "pk-1"})

    assert output["attestation"] is not None
    assert output["result"]["value"] == 42
    assert adapter.verify_task_output(output, identity.public_key_pem)


def test_crewai_error_is_attested():
    identity = MockIdentity()
    adapter = TrustHandoffCrewAIAdapter(identity)

    def task(inputs):
        raise RuntimeError("boom")

    wrapped = adapter.wrap_task(task)

    output = wrapped({"packet_id": "pk-2"})

    assert output["attestation"] is not None
    assert output["result"]["error"] == "boom"
    assert output["result"]["error_type"] == "RuntimeError"


def test_crewai_missing_packet_id_raises():
    identity = MockIdentity()
    adapter = TrustHandoffCrewAIAdapter(identity)

    def task(inputs):
        return {"value": 1}

    wrapped = adapter.wrap_task(task)

    with pytest.raises(ValueError):
        wrapped({})


def test_crewai_programming_error_not_swallowed():
    identity = MockIdentity()
    adapter = TrustHandoffCrewAIAdapter(identity)

    def task(inputs):
        return {"score": 1.5}  # float forbidden by attestation payload validation

    wrapped = adapter.wrap_task(task)

    with pytest.raises(TypeError):
        wrapped({"packet_id": "pk-3"})


def test_crewai_verify_serialized_attestation():
    identity = MockIdentity()
    adapter = TrustHandoffCrewAIAdapter(identity)

    def task(inputs):
        return {"value": "serialized"}

    wrapped = adapter.wrap_task(task)
    output = wrapped({"packet_id": "pk-4"})

    serialized_output = {
        "result": output["result"],
        "attestation": output["attestation"].model_dump(),
    }

    assert adapter.verify_task_output(serialized_output, identity.public_key_pem)


def test_crewai_verify_rejects_stale_attestation():
    identity = MockIdentity()
    adapter = TrustHandoffCrewAIAdapter(identity)

    def task(inputs):
        return {"value": 42}

    wrapped = adapter.wrap_task(task)
    output = wrapped({"packet_id": "pk-5"})

    stale_now = output["attestation"].timestamp_ms + 600_000

    assert not adapter.verify_task_output(
        output,
        identity.public_key_pem,
        max_age_seconds=300,
        current_timestamp_ms=stale_now,
    )
