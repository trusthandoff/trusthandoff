from trusthandoff import CapabilityRevocationRegistry


def test_capability_revocation_registry():
    registry = CapabilityRevocationRegistry()

    assert registry.is_revoked("cap-1") is False

    registry.revoke("cap-1")

    assert registry.is_revoked("cap-1") is True
    assert registry.is_revoked("cap-2") is False
