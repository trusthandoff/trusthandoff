from .chain import DelegationChain
from .delegation_scope import delegation_scope_check


def validate_delegation_chain(chain: DelegationChain) -> bool:
    """
    Validates that authority never increases across delegation hops.

    For every consecutive pair of hops:
    child_permissions must be a subset of parent_permissions.
    """

    if len(chain.hops) <= 1:
        return True

    for i in range(1, len(chain.hops)):
        parent = chain.hops[i - 1].delegated_permissions
        child = chain.hops[i].delegated_permissions

        if not delegation_scope_check(parent, child):
            return False

    return True
