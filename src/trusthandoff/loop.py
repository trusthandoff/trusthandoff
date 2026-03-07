from .chain import DelegationChain


def detects_loop(chain: DelegationChain, next_agent_id: str) -> bool:
    """
    Returns True if the next agent already exists in the delegation chain.
    """

    return next_agent_id in chain.agents
