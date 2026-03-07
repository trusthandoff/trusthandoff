from datetime import datetime, timezone

from .packet import SignedTaskPacket


def validate_packet(packet: SignedTaskPacket) -> bool:
    now = datetime.now(timezone.utc)

    if packet.issued_at > packet.expires_at:
        return False

    if packet.expires_at < now:
        return False

    return True
