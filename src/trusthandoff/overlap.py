from datetime import datetime, timedelta, timezone
from typing import Dict, Optional


OVERLAP_SECONDS = 30


class OverlapBackend:
    def register(self, token_id: str) -> None:
        raise NotImplementedError

    def is_valid(self, token_id: str) -> bool:
        raise NotImplementedError


class InMemoryOverlapBackend(OverlapBackend):
    def __init__(self):
        self._store: Dict[str, datetime] = {}

    def register(self, token_id: str) -> None:
        self._store[token_id] = datetime.now(timezone.utc)

    def is_valid(self, token_id: str) -> bool:
        ts = self._store.get(token_id)
        if ts is None:
            return False
        return (datetime.now(timezone.utc) - ts) <= timedelta(seconds=OVERLAP_SECONDS)


# GLOBAL BACKEND (can be swapped)
_backend: OverlapBackend = InMemoryOverlapBackend()


def set_overlap_backend(backend: OverlapBackend) -> None:
    global _backend
    _backend = backend


def register_overlap(token_id: str) -> None:
    _backend.register(token_id)


def is_overlap_valid(token_id: str) -> bool:
    return _backend.is_valid(token_id)
