from trusthandoff import (
    DelegationChain,
    DelegationHop,
    Permissions,
    validate_delegation_chain,
)


def test_validate_delegation_chain_accepts_monotonic_reduction():
    hop1 = DelegationHop(
        agent_id="agent:a",
        delegated_permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=5,
        ),
    )

    hop2 = DelegationHop(
        agent_id="agent:b",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=3,
        ),
    )

    hop3 = DelegationHop(
        agent_id="agent:c",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
    )

    chain = DelegationChain(
        packet_ids=["pk1", "pk2", "pk3"],
        agents=["agent:a", "agent:b", "agent:c"],
        hops=[hop1, hop2, hop3],
    )

    assert validate_delegation_chain(chain) is True


def test_validate_delegation_chain_rejects_authority_escalation():
    hop1 = DelegationHop(
        agent_id="agent:a",
        delegated_permissions=Permissions(
            allowed_actions=["search"],
            max_tool_calls=2,
        ),
    )

    hop2 = DelegationHop(
        agent_id="agent:b",
        delegated_permissions=Permissions(
            allowed_actions=["search", "write"],
            max_tool_calls=2,
        ),
    )

    chain = DelegationChain(
        packet_ids=["pk1", "pk2"],
        agents=["agent:a", "agent:b"],
        hops=[hop1, hop2],
    )

    assert validate_delegation_chain(chain) is False
