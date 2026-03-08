import json
from datetime import datetime

from .envelope import DelegationEnvelope
from .envelope_serialization import envelope_from_dict, envelope_to_dict


def _serialize(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type not serializable: {type(obj)}")


def envelope_to_json(envelope: DelegationEnvelope) -> str:
    data = envelope_to_dict(envelope)
    return json.dumps(data, sort_keys=True, default=_serialize)


def envelope_from_json(payload: str) -> DelegationEnvelope:
    data = json.loads(payload)
    return envelope_from_dict(data)
