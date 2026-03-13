import time
from collections import OrderedDict


class ReplayGuard:
    """
    Simple in-memory replay protection using (agent_id, nonce).
    Bounded size + TTL eviction.
    """

    def __init__(self, ttl_seconds: int = 600, max_entries: int = 10000):
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._store = OrderedDict()

    def _purge(self):
        now = time.time()

        # purge expired
        keys_to_delete = [
            key for key, ts in self._store.items()
            if now - ts > self.ttl
        ]

        for k in keys_to_delete:
            self._store.pop(k, None)

        # enforce max size
        while len(self._store) > self.max_entries:
            self._store.popitem(last=False)

    def seen(self, agent_id: str, nonce: str) -> bool:
        key = (agent_id, nonce)
        self._purge()

        if key in self._store:
            return True

        self._store[key] = time.time()
        return False
