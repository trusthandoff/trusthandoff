from typing import Literal, Optional

from pydantic import BaseModel


class PacketDecision(BaseModel):
    packet_id: str
    decision: Literal["ACCEPT", "REJECT"]
    reason: Optional[str] = None
