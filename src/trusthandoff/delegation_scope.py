from .packet import Permissions


def delegation_scope_check(parent: Permissions, child: Permissions) -> bool:
    """
    Ensure delegated permissions never exceed the parent's permissions.
    """

    # allowed actions must be subset
    if not set(child.allowed_actions).issubset(set(parent.allowed_actions)):
        return False

    # tool call limits cannot increase
    if child.max_tool_calls is not None and parent.max_tool_calls is not None:
        if child.max_tool_calls > parent.max_tool_calls:
            return False

    return True
