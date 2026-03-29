import threading
from typing import Optional


class RevocationBackend:
    def revoke(self, capability_id: str) -> None:
        raise NotImplementedError

    def is_revoked(self, capability_id: str) -> bool:
        raise NotImplementedError


class InMemoryRevocationBackend(RevocationBackend):
    def __init__(self):
        self._revoked_ids = set()
        self._lock = threading.Lock()

    def revoke(self, capability_id: str) -> None:
        with self._lock:
            self._revoked_ids.add(capability_id)

    def is_revoked(self, capability_id: str) -> bool:
        with self._lock:
            return capability_id in self._revoked_ids


class RedisRevocationBackend(RevocationBackend):
    """
    Redis-backed revocation registry.

    Revocations are stored as durable keys by default.
    """
    def __init__(self, redis_url: str, key_prefix: str = "trusthandoff:revocation:"):
        try:
            import redis
        except ImportError as exc:
            raise ImportError(
                "RedisRevocationBackend requires the 'redis' package. "
                "Install it with: pip install redis"
            ) from exc

        self.client = redis.from_url(redis_url)
        self.key_prefix = key_prefix

    def revoke(self, capability_id: str) -> None:
        key = f"{self.key_prefix}{capability_id}"
        self.client.set(key, "1")

    def is_revoked(self, capability_id: str) -> bool:
        key = f"{self.key_prefix}{capability_id}"
        return bool(self.client.exists(key))


_backend: Optional[RevocationBackend] = None


def set_revocation_backend(backend: RevocationBackend) -> None:
    global _backend
    _backend = backend


class CapabilityRevocationRegistry:
    """
    Backward-compatible facade.

    Behavior:
    - if backend is explicitly provided, use it
    - else if a global backend was configured, use it
    - else create a fresh isolated in-memory backend
    """
    def __init__(self, backend: Optional[RevocationBackend] = None):
        if backend is not None:
            self._backend = backend
        elif _backend is not None:
            self._backend = _backend
        else:
            self._backend = InMemoryRevocationBackend()

    def revoke(self, capability_id: str) -> None:
        self._backend.revoke(capability_id)

    def is_revoked(self, capability_id: str) -> bool:
        return self._backend.is_revoked(capability_id)
