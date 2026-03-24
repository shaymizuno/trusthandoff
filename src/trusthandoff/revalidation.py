import logging
import random
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from .errors import StaleCapabilityError, RevocationConsistencyError

logger = logging.getLogger(__name__)


@dataclass
class RevalidationState:
    stale_detected: bool = False
    stale_reason: Optional[str] = None
    is_revocation_stale: bool = False


class RevalidationWatcher:
    """
    Lightweight background revalidator for long-running tasks.

    Behavior:
    - If revalidate_every_seconds is None or <= 0, the watcher is disabled.
    - Otherwise, it periodically calls `revalidate_fn`.
    - If `revalidate_fn` returns False, the capability is marked stale.
    - If `revalidate_fn` raises, the capability is marked stale with the exception message.
    - Caller is responsible for calling `raise_if_stale()`.
    """

    MIN_INTERVAL_SECONDS = 0.5

    def __init__(
        self,
        revalidate_fn: Callable[[], bool],
        capability_id: str,
        revalidate_every_seconds: Optional[float] = None,
        logger_: Optional[logging.Logger] = None,
        jitter: float = 0.2,
    ):
        if not capability_id:
            raise ValueError("capability_id must be a non-empty string")

        if jitter < 0 or jitter > 1:
            raise ValueError("jitter must be between 0 and 1")

        self.revalidate_fn = revalidate_fn
        self.capability_id = capability_id
        self.revalidate_every_seconds = revalidate_every_seconds
        self.logger = logger_ or logger
        self.jitter = jitter

        self.state = RevalidationState()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def enabled(self) -> bool:
        return (
            self.revalidate_every_seconds is not None
            and self.revalidate_every_seconds > 0
        )

    def start(self) -> None:
        if not self.enabled:
            return

        if self._thread is not None and self._thread.is_alive():
            return

        self._thread = threading.Thread(
            target=self._run,
            name=f"trusthandoff-revalidation-{self.capability_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 1.0) -> None:
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.stop()

    def raise_if_stale(self) -> None:
        with self._lock:
            if not self.state.stale_detected:
                return

            if self.state.is_revocation_stale:
                raise RevocationConsistencyError(
                    token_id=self.capability_id,
                    detail=self.state.stale_reason or "stale_revocation_state",
                )

            raise StaleCapabilityError(
                capability_id=self.capability_id,
                reason=self.state.stale_reason or "stale_detected",
            )

    def _mark_stale(self, reason: str, is_revocation: bool = False) -> None:
        with self._lock:
            self.state.stale_reason = reason
            self.state.is_revocation_stale = is_revocation
            self.state.stale_detected = True

        self.logger.warning(
            "Revalidation detected stale capability",
            extra={
                "capability_id": self.capability_id,
                "reason": reason,
                "is_revocation": is_revocation,
            },
        )

    def _effective_interval(self) -> float:
        assert self.revalidate_every_seconds is not None

        base = max(self.revalidate_every_seconds, self.MIN_INTERVAL_SECONDS)

        if self.jitter == 0:
            return base

        delta = random.uniform(-self.jitter, self.jitter) * base
        return max(self.MIN_INTERVAL_SECONDS, base + delta)

    def _run(self) -> None:
        while not self._stop_event.wait(self._effective_interval()):
            try:
                ok = self.revalidate_fn()
            except Exception as exc:
                self._mark_stale(
                    f"revalidation_exception:{type(exc).__name__}:{exc}",
                    is_revocation=False,
                )
                return

            if not ok:
                self._mark_stale("revalidation_failed", is_revocation=False)
                return
