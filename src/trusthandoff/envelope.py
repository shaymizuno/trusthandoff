from pydantic import BaseModel

from .chain import DelegationChain
from .packet import SignedTaskPacket


class DelegationEnvelope(BaseModel):
    packet: SignedTaskPacket
    chain: DelegationChain
