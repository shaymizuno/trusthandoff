import threading
from typing import Optional


class ReplayBackend:
    def check_and_store(self, nonce: str) -> bool:
        raise NotImplementedError


class InMemoryReplayBackend(ReplayBackend):
    def __init__(self):
        self._seen_nonces = set()
        self._lock = threading.Lock()

    def check_and_store(self, nonce: str) -> bool:
        with self._lock:
            if nonce in self._seen_nonces:
                return False
            self._seen_nonces.add(nonce)
            return True


class RedisReplayBackend(ReplayBackend):
    """
    Redis-backed replay protection.

    Uses SETNX semantics:
    - True if nonce was new
    - False if nonce already existed

    Optional ttl_seconds lets replay entries expire.
    """

    def __init__(
        self,
        redis_url: str,
        ttl_seconds: Optional[int] = None,
        key_prefix: str = "trusthandoff:replay:",
    ):
        try:
            import redis
        except ImportError as exc:
            raise ImportError(
                "RedisReplayBackend requires the 'redis' package. "
                "Install it with: pip install redis"
            ) from exc

        self.client = redis.from_url(redis_url)
        self.ttl_seconds = ttl_seconds
        self.key_prefix = key_prefix

    def check_and_store(self, nonce: str) -> bool:
        key = f"{self.key_prefix}{nonce}"
        inserted = self.client.setnx(key, "1")
        if inserted and self.ttl_seconds is not None:
            self.client.expire(key, self.ttl_seconds)
        return bool(inserted)


_backend: Optional[ReplayBackend] = None


def set_replay_backend(backend: ReplayBackend) -> None:
    global _backend
    _backend = backend


class ReplayProtection:
    """
    Backward-compatible facade.

    Behavior:
    - if backend is explicitly provided, use it
    - else if a global backend was configured, use it
    - else create a fresh isolated in-memory backend
    """

    def __init__(self, backend: Optional[ReplayBackend] = None):
        if backend is not None:
            self._backend = backend
        elif _backend is not None:
            self._backend = _backend
        else:
            self._backend = InMemoryReplayBackend()

    def check_and_store(self, nonce: str) -> bool:
        return self._backend.check_and_store(nonce)
