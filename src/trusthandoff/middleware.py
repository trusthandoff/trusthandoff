from .decision import PacketDecision
from .envelope import DelegationEnvelope
from .handoff import process_handoff
from .replay import ReplayProtection
from .depth import within_max_depth


class TrustHandoffMiddleware:
    """
    Minimal middleware entrypoint for TrustHandoff.
    """

    def __init__(
        self,
        replay_protection: ReplayProtection | None = None,
        max_depth: int = 5,
    ):
        self.replay_protection = replay_protection or ReplayProtection()
        self.max_depth = max_depth

    def handle(self, envelope: DelegationEnvelope) -> PacketDecision:
        nonce = envelope.packet.nonce

        if not self.replay_protection.check_and_store(nonce):
            return PacketDecision(
                packet_id=envelope.packet.packet_id,
                decision="REJECT",
                reason="Replay detected",
            )

        if not within_max_depth(envelope.chain, self.max_depth):
            return PacketDecision(
                packet_id=envelope.packet.packet_id,
                decision="REJECT",
                reason="Delegation depth exceeded",
            )

        return process_handoff(envelope.packet)
