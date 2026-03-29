from typing import Optional
import threading


class CoordinationBackend:
    def acquire(self, name: str, ttl_seconds: int = 10) -> bool:
        raise NotImplementedError

    def release(self, name: str) -> None:
        raise NotImplementedError


class InMemoryCoordinationBackend(CoordinationBackend):
    """
    Minimal single-process coordination backend.
    Good enough for local/dev mode.
    """

    def __init__(self):
        self._locks = set()
        self._lock = threading.Lock()

    def acquire(self, name: str, ttl_seconds: int = 10) -> bool:
        with self._lock:
            if name in self._locks:
                return False
            self._locks.add(name)
            return True

    def release(self, name: str) -> None:
        with self._lock:
            self._locks.discard(name)


class RedisCoordinationBackend(CoordinationBackend):
    """
    Minimal distributed lock on Redis.
    Uses SET NX EX.
    """

    def __init__(self, redis_url: str, key_prefix: str = "trusthandoff:lock:"):
        try:
            import redis
        except ImportError as exc:
            raise ImportError(
                "RedisCoordinationBackend requires the 'redis' package. "
                "Install it with: pip install redis"
            ) from exc

        self.client = redis.from_url(redis_url)
        self.key_prefix = key_prefix

    def acquire(self, name: str, ttl_seconds: int = 10) -> bool:
        key = f"{self.key_prefix}{name}"
        return bool(self.client.set(key, "1", nx=True, ex=ttl_seconds))

    def release(self, name: str) -> None:
        key = f"{self.key_prefix}{name}"
        self.client.delete(key)


_backend: Optional[CoordinationBackend] = None


def set_coordination_backend(backend: CoordinationBackend) -> None:
    global _backend
    _backend = backend


class CoordinationLock:
    """
    Backward-compatible facade.
    """

    def __init__(self, backend: Optional[CoordinationBackend] = None):
        if backend is not None:
            self._backend = backend
        elif _backend is not None:
            self._backend = _backend
        else:
            self._backend = InMemoryCoordinationBackend()

    def acquire(self, name: str, ttl_seconds: int = 10) -> bool:
        return self._backend.acquire(name, ttl_seconds)

    def release(self, name: str) -> None:
        self._backend.release(name)
