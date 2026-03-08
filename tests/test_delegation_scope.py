from trusthandoff.packet import Permissions
from trusthandoff.delegation_scope import delegation_scope_check


def test_valid_delegation_subset():
    parent = Permissions(
        allowed_actions=["read", "search"],
        max_tool_calls=5
    )

    child = Permissions(
        allowed_actions=["search"],
        max_tool_calls=3
    )

    assert delegation_scope_check(parent, child) is True


def test_invalid_action_escalation():
    parent = Permissions(
        allowed_actions=["search"]
    )

    child = Permissions(
        allowed_actions=["search", "write"]
    )

    assert delegation_scope_check(parent, child) is False


def test_invalid_tool_call_escalation():
    parent = Permissions(
        allowed_actions=["read"],
        max_tool_calls=2
    )

    child = Permissions(
        allowed_actions=["read"],
        max_tool_calls=5
    )

    assert delegation_scope_check(parent, child) is False


def test_equal_permissions_allowed():
    parent = Permissions(
        allowed_actions=["read"],
        max_tool_calls=2
    )

    child = Permissions(
        allowed_actions=["read"],
        max_tool_calls=2
    )

    assert delegation_scope_check(parent, child) is True
