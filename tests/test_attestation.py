import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from trusthandoff.attestation import (
    create_attestation,
    verify_attestation,
)


class MockIdentity:
    def __init__(self):
        self.agent_id = "agent-test"
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key()

        pem = self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key_pem = pem.decode()

    def sign(self, data: bytes) -> bytes:
        return self.private.sign(data)


def test_honest_roundtrip():
    identity = MockIdentity()

    result = {"ok": True}
    att = create_attestation("p1", result, identity)

    assert verify_attestation(att, identity.public_key_pem, result=result)


def test_wrong_result():
    identity = MockIdentity()

    att = create_attestation("p1", {"a": 1}, identity)

    assert not verify_attestation(att, identity.public_key_pem, result={"a": 2})


def test_wrong_key():
    id1 = MockIdentity()
    id2 = MockIdentity()

    att = create_attestation("p1", {"x": 1}, id1)

    assert not verify_attestation(att, id2.public_key_pem, result={"x": 1})


def test_expired():
    identity = MockIdentity()

    att = create_attestation("p1", {"x": 1}, identity)

    old_time = att.timestamp_ms + 600_000

    assert not verify_attestation(
        att,
        identity.public_key_pem,
        result={"x": 1},
        now_ms=old_time,
    )


def test_future_reject():
    identity = MockIdentity()

    att = create_attestation("p1", {"x": 1}, identity)

    future = att.timestamp_ms - 60_000

    assert not verify_attestation(
        att,
        identity.public_key_pem,
        result={"x": 1},
        now_ms=future,
    )


def test_float_rejected():
    identity = MockIdentity()

    with pytest.raises(TypeError):
        create_attestation("p1", {"x": 1.2}, identity)


def test_reason_mismatch():
    identity = MockIdentity()

    att = create_attestation("p1", {"x": 1}, identity, reason={"r": 1})

    assert not verify_attestation(
        att,
        identity.public_key_pem,
        result={"x": 1},
        reason={"r": 2},
    )
