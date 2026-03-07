from .packet import SignedTaskPacket


def packet_to_dict(packet: SignedTaskPacket) -> dict:
    return packet.model_dump()


def packet_from_dict(data: dict) -> SignedTaskPacket:
    return SignedTaskPacket(**data)
