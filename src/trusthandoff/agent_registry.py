class AgentRegistry:
    """
    Minimal in-memory registry mapping agent_id -> public_key.
    """

    def __init__(self):
        self._registry = {}
        self._revoked = set()

    def register(self, agent_id: str, public_key: str) -> None:
        self._registry[agent_id] = public_key

    def resolve(self, agent_id: str) -> str | None:
        return self._registry.get(agent_id)

    def is_registered(self, agent_id: str) -> bool:
        return agent_id in self._registry

    def revoke(self, agent_id: str) -> None :
        self._revoked.add(agent_id)

    def is_revoked(self, agent_id: str) -> bool:
        return agent_id in self._revoked
