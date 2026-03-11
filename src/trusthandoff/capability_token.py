import base64
import json

from .capability import DelegationCapability


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def encode_capability_token(capability: DelegationCapability) -> str:
    """
    Encode a DelegationCapability as a portable base64url token.
    """
    payload = capability.model_dump(mode="json")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64url_encode(raw)


def decode_capability_token(token: str) -> DelegationCapability:
    """
    Decode a base64url capability token back into a DelegationCapability.
    """
    raw = _b64url_decode(token)
    payload = json.loads(raw.decode("utf-8"))
    return DelegationCapability(**payload)
