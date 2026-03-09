from typing import List
from pydantic import BaseModel, Field

from .hop import DelegationHop


class DelegationChain(BaseModel):
    """
    Tracks the chain of delegation across multiple agents.
    """

    packet_ids: List[str]
    agents: List[str]
    hops: List[DelegationHop] = Field(default_factory=list)

    def add_handoff(self, packet_id: str, agent_id: str):
        """
        Record a new delegation step.
        """
        self.packet_ids.append(packet_id)
        self.agents.append(agent_id)

    def depth(self) -> int:
        """
        Return the number of delegation steps.
        """
        return len(self.packet_ids)
