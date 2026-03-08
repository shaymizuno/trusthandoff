from .envelope import DelegationEnvelope


def envelope_to_dict(envelope: DelegationEnvelope) -> dict:
    return envelope.model_dump()


def envelope_from_dict(data: dict) -> DelegationEnvelope:
    return DelegationEnvelope(**data)
