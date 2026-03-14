from typing import Callable

from trusthandoff.capability import DelegationCapability
from trusthandoff.packet import SignedTaskPacket


def check_permission_narrowing(parent: SignedTaskPacket, child: SignedTaskPacket) -> bool:
    """
    Ensure that delegated permissions do not expand authority.

    Child permissions must be a subset of parent permissions.
    """
    parent_actions = set(parent.permissions.allowed_actions)
    child_actions = set(child.permissions.allowed_actions)

    return child_actions.issubset(parent_actions)


DelegationPolicy = Callable[[DelegationCapability, str], tuple[bool, str | None]]


def allow_all_policy(capability: DelegationCapability, action: str) -> tuple[bool, str | None]:
    return True, None


def deny_file_write_policy(capability: DelegationCapability, action: str) -> tuple[bool, str | None]:
    if action == "file_write":
        return False, "policy_denied:file_write"
    return True, None
