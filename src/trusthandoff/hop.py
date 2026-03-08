from pydantic import BaseModel

from .packet import Permissions


class DelegationHop(BaseModel):
    agent_id: str
    delegated_permissions: Permissions
