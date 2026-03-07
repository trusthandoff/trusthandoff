from .decision import PacketDecision
from .packet import SignedTaskPacket
from .validation import validate_packet
from .verification import verify_packet


def process_handoff(packet: SignedTaskPacket) -> PacketDecision:
    if not verify_packet(packet):
        return PacketDecision(
            packet_id=packet.packet_id,
            decision="REJECT",
            reason="Invalid signature",
        )

    if not validate_packet(packet):
        return PacketDecision(
            packet_id=packet.packet_id,
            decision="REJECT",
            reason="Packet validation failed",
        )

    return PacketDecision(
        packet_id=packet.packet_id,
        decision="ACCEPT",
        reason="Packet verified and valid",
    )
