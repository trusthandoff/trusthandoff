from trusthandoff import DelegationChain, DelegationHop, Permissions


def test_delegation_hop_model():
    hop = DelegationHop(
        agent_id="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read", "search"],
            max_tool_calls=3,
        ),
    )

    assert hop.agent_id == "agent:research:beta"
    assert hop.delegated_permissions.allowed_actions == ["read", "search"]
    assert hop.delegated_permissions.max_tool_calls == 3


def test_delegation_chain_accepts_hops():
    hop = DelegationHop(
        agent_id="agent:research:beta",
        delegated_permissions=Permissions(
            allowed_actions=["read"],
            max_tool_calls=2,
        ),
    )

    chain = DelegationChain(
        packet_ids=["pk_001"],
        agents=["agent:planner:alpha"],
        hops=[hop],
    )

    assert len(chain.hops) == 1
    assert chain.hops[0].agent_id == "agent:research:beta"
    assert chain.hops[0].delegated_permissions.allowed_actions == ["read"]
