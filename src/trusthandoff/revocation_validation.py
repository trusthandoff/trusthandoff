from .capability import DelegationCapability
from .revocation import CapabilityRevocationRegistry


def is_chain_revoked(
    capabilities: list[DelegationCapability],
    revocation_registry: CapabilityRevocationRegistry,
) -> bool:
    """
    Returns True if any capability in the chain has been revoked.
    """

    for cap in capabilities:
        if revocation_registry.is_revoked(cap.capability_id):
            return True

    return False
