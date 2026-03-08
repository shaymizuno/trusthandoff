from dataclasses import dataclass


@dataclass
class PacketDecision:
    accepted: bool
    reason: str

    @classmethod
    def accept(cls, reason: str = "Packet verified and valid"):
        return cls(True, reason)

    @classmethod
    def reject(cls, reason: str):
        return cls(False, reason)
