import logging
import random
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from .errors import StaleCapabilityError, RevocationConsistencyError
from .events import emit_event

logger = logging.getLogger(__name__)


@dataclass
class RevalidationState:
    stale_detected: bool = False
    stale_reason: Optional[str] = None
    is_revocation_stale: bool = False

    # Basic observability
    last_checked_at: Optional[datetime] = None
    last_result: Optional[bool] = None
    elapsed_seconds: float = 0.0
    last_error: Optional[str] = None


class RevalidationWatcher:
    """
    Lightweight background revalidator for long-running tasks.

    Behavior:
    - If revalidate_every_seconds is None or <= 0, the watcher is disabled.
    - Otherwise, it periodically calls `revalidate_fn`.
    - If `revalidate_fn` returns False, the capability is marked stale.
    - If `revalidate_fn` raises, the capability is marked stale with the exception message.
    - If `expires_at` is set and current time passes it, the capability is marked stale.
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
        expires_at: Optional[datetime] = None,
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
        self.expires_at = expires_at

        self.state = RevalidationState()

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._started_at: Optional[float] = None

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

        self._started_at = time.time()
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
            "Revalidation watcher marked capability stale",
            extra={
                "capability_id": self.capability_id,
                "reason": reason,
                "is_revocation_stale": is_revocation,
            },
        )

        emit_event(
            "capability_stale",
            {
                "capability_id": self.capability_id,
                "reason": reason,
                "is_revocation_stale": is_revocation,
            },
        )

    def _record_check(self, result: Optional[bool], error: Optional[str] = None) -> None:
        now = datetime.now(timezone.utc)
        with self._lock:
            self.state.last_checked_at = now
            self.state.last_result = result
            self.state.last_error = error
            if self._started_at is not None:
                self.state.elapsed_seconds = time.time() - self._started_at

    def _check_expiry(self) -> bool:
        if self.expires_at is None:
            return True

        now = datetime.now(timezone.utc)
        if now >= self.expires_at:
            self._record_check(False, "expired_by_revalidation_watcher")
            self._mark_stale("expired_by_revalidation_watcher")
            return False

        return True

    def _effective_interval(self) -> float:
        """
        Backward-compatible alias used by tests and older code.
        """
        assert self.revalidate_every_seconds is not None
        return max(self.revalidate_every_seconds, self.MIN_INTERVAL_SECONDS)


    def _compute_sleep_interval(self) -> float:
        assert self.revalidate_every_seconds is not None

        base = max(self.revalidate_every_seconds, self.MIN_INTERVAL_SECONDS)
        if self.jitter == 0:
            return base

        low = base * (1 - self.jitter)
        high = base * (1 + self.jitter)
        return max(self.MIN_INTERVAL_SECONDS, random.uniform(low, high))

    def _run(self) -> None:
        while not self._stop_event.is_set():
            if not self._check_expiry():
                return

            try:
                result = self.revalidate_fn()
                self._record_check(bool(result), None)

                if not result:
                    self._mark_stale("revalidation_failed")
                    return

            except RevocationConsistencyError as exc:
                self._record_check(False, str(exc))
                self._mark_stale(str(exc), is_revocation=True)
                return


            except Exception as exc:
                self._record_check(False, str(exc))
                self._mark_stale(
                    f"revalidation_exception:{type(exc).__name__}:{exc}"
                )
                return

            sleep_for = self._compute_sleep_interval()
            if self._stop_event.wait(timeout=sleep_for):
                return
