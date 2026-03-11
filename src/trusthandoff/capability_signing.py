import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .capability import DelegationCapability


def _canonical_capability_payload(capability: DelegationCapability) -> bytes:
    payload = capability.model_dump(exclude={"signature"})
    return json.dumps(payload, sort_keys=True, default=str).encode("utf-8")


def sign_capability(capability: DelegationCapability, private_key_pem: str) -> DelegationCapability:
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Capability signing requires an Ed25519 private key")

    signature = private_key.sign(_canonical_capability_payload(capability))
    capability.signature = base64.b64encode(signature).decode("utf-8")
    return capability


def verify_capability_signature(capability: DelegationCapability) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            capability.public_key.encode("utf-8")
        )

        if not isinstance(public_key, Ed25519PublicKey):
            return False

        public_key.verify(
            base64.b64decode(capability.signature.encode("utf-8")),
            _canonical_capability_payload(capability),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
