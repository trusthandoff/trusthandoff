class CapabilityRevocationRegistry:
    """
    Minimal in-memory registry for revoked capability IDs.
    """

    def __init__(self):
        self._revoked_ids = set()

    def revoke(self, capability_id: str) -> None:
        self._revoked_ids.add(capability_id)

    def is_revoked(self, capability_id: str) -> bool:
        return capability_id in self._revoked_ids
