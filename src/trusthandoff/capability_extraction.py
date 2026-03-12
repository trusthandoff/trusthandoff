from typing import Optional
from .packet import SignedTaskPacket


def extract_capability_token(packet: SignedTaskPacket) -> Optional[str]:
    """
    Extract capability token from packet if present.

    This isolates capability handling from packet transport logic.
    """

    if packet.capability_token is None:
        return None

    return packet.capability_token
