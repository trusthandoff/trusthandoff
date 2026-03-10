from .capability import DelegationCapability
from .capability_validation import validate_capability_derivation


def validate_capability_chain(capabilities: list[DelegationCapability]) -> bool:
    """
    Validates a full capability derivation chain.

    Each capability must be a valid derivation of the previous one.
    """

    if len(capabilities) <= 1:
        return True

    for i in range(1, len(capabilities)):
        parent = capabilities[i - 1]
        child = capabilities[i]

        if not validate_capability_derivation(parent, child):
            return False

    return True
