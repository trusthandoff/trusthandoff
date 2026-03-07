from trusthandoff import DelegationChain, detects_loop


def test_detects_loop_returns_false_for_new_agent():
    chain = DelegationChain(
        packet_ids=["pk_001", "pk_002"],
        agents=["agent:a", "agent:b"],
    )

    assert detects_loop(chain, "agent:c") is False


def test_detects_loop_returns_true_for_existing_agent():
    chain = DelegationChain(
        packet_ids=["pk_001", "pk_002"],
        agents=["agent:a", "agent:b"],
    )

    assert detects_loop(chain, "agent:a") is True
