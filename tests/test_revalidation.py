from trusthandoff.errors import (
    StaleCapabilityError,
    RevocationConsistencyError,
)

from trusthandoff.revalidation import RevalidationWatcher
import time
import pytest



def test_revalidation_triggers_stale():
    called = {"ok": True}

    def revalidate():
        return called["ok"]

    watcher = RevalidationWatcher(
        revalidate_fn=revalidate,
        capability_id="test-cap",
        revalidate_every_seconds=0.2,
    )

    with watcher:
        time.sleep(0.65)
        called["ok"] = False
        time.sleep(0.65)

        with pytest.raises(StaleCapabilityError):
            watcher.raise_if_stale()


def test_revalidation_watcher_disabled_by_default():
    watcher = RevalidationWatcher(
        revalidate_fn=lambda: True,
        capability_id="cap-1",
        revalidate_every_seconds=None,
    )

    assert watcher.enabled is False
    watcher.start()  # should do nothing
    assert watcher._thread is None


def test_revalidation_watcher_starts_when_enabled():
    watcher = RevalidationWatcher(
        revalidate_fn=lambda: True,
        capability_id="cap-2",
        revalidate_every_seconds=0.5,
        jitter=0.0,
    )

    assert watcher.enabled is True
    watcher.start()
    assert watcher._thread is not None
    assert watcher._thread.is_alive() is True
    watcher.stop()


def test_revalidation_triggers_stale():
    state = {"ok": True}

    def revalidate():
        return state["ok"]

    watcher = RevalidationWatcher(
        revalidate_fn=revalidate,
        capability_id="cap-3",
        revalidate_every_seconds=0.2,
        jitter=0.0,
    )

    watcher.start()
    time.sleep(0.55)

    state["ok"] = False
    time.sleep(0.65)

    assert watcher.state.stale_detected is True
    assert watcher.state.stale_reason == "revalidation_failed"

    with pytest.raises(StaleCapabilityError):
        watcher.raise_if_stale()

    watcher.stop()


def test_revalidation_exception_marks_stale():
    def revalidate():
        raise RuntimeError("boom")

    watcher = RevalidationWatcher(
        revalidate_fn=revalidate,
        capability_id="cap-4",
        revalidate_every_seconds=0.2,
        jitter=0.0,
    )

    watcher.start()
    time.sleep(0.65)

    assert watcher.state.stale_detected is True
    assert "revalidation_exception:RuntimeError:boom" in watcher.state.stale_reason

    with pytest.raises(StaleCapabilityError):
        watcher.raise_if_stale()

    watcher.stop()


def test_revalidation_revocation_flag_raises_specific_error():
    watcher = RevalidationWatcher(
        revalidate_fn=lambda: True,
        capability_id="cap-5",
        revalidate_every_seconds=0.2,
        jitter=0.0,
    )

    watcher._mark_stale("revocation_store_stale", is_revocation=True)

    assert watcher.state.stale_detected is True
    assert watcher.state.is_revocation_stale is True

    with pytest.raises(RevocationConsistencyError):
        watcher.raise_if_stale()


def test_revalidation_context_manager_starts_and_stops():
    watcher = RevalidationWatcher(
        revalidate_fn=lambda: True,
        capability_id="cap-6",
        revalidate_every_seconds=0.5,
        jitter=0.0,
    )

    with watcher as active:
        assert active is watcher
        assert watcher._thread is not None
        assert watcher._thread.is_alive() is True

    if watcher._thread is not None:
        assert watcher._thread.is_alive() is False


def test_revalidation_min_interval_floor():
    watcher = RevalidationWatcher(
        revalidate_fn=lambda: True,
        capability_id="cap-7",
        revalidate_every_seconds=0.1,
        jitter=0.0,
    )

    assert watcher._effective_interval() == watcher.MIN_INTERVAL_SECONDS


def test_revalidation_invalid_jitter_rejected():
    with pytest.raises(ValueError):
        RevalidationWatcher(
            revalidate_fn=lambda: True,
            capability_id="cap-8",
            revalidate_every_seconds=1.0,
            jitter=-0.1,
        )

    with pytest.raises(ValueError):
        RevalidationWatcher(
            revalidate_fn=lambda: True,
            capability_id="cap-9",
            revalidate_every_seconds=1.0,
            jitter=1.5,
        )


def test_revalidation_empty_capability_id_rejected():
    with pytest.raises(ValueError):
        RevalidationWatcher(
            revalidate_fn=lambda: True,
            capability_id="",
            revalidate_every_seconds=1.0,
        )
