from datetime import datetime
from typing import Any, Dict

from pydantic import BaseModel, Field


class CapabilityTokenEnvelope(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)
    capability_token: str
    nonce: str
    issued_at: datetime
