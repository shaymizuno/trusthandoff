import time

from trusthandoff.middleware import TrustHandoffMiddleware
from trusthandoff.revalidation import RevalidationWatcher


class DummyReplayProtection:
    def check_and_store(self, nonce):
        return True


class DummyChain:
    def __init__(self):
        self.agents = ["a", "b"]

    def depth(self):
        return len(self.agents)


class DummyPacket:
    def __init__(self, packet_id="pkt-1", nonce="nonce-1"):
        self.packet_id = packet_id
        self.nonce = nonce

        self.task_id = "task-1"
        self.from_agent = "agent-a"
        self.to_agent = "agent-b"
        self.intent = "demo"

        self.issued_at = type("T", (), {"isoformat": lambda self: "2026-01-01T00:00:00"})()
        self.expires_at = type("T", (), {"isoformat": lambda self: "2026-01-01T01:00:00"})()
        self.signature = "sig-preview"

    # these are used deeper by existing validation/verification paths in some setups
    public_key = "pk"
    constraints = None
    permissions = None
    provenance = None


class DummyEnvelope:
    def __init__(self, packet_id="pkt-1", nonce="nonce-1"):
        self.packet = DummyPacket(packet_id=packet_id, nonce=nonce)
        self.chain = DummyChain()


def test_handle_with_revalidation_returns_watcher_on_accept(monkeypatch):
    envelope = DummyEnvelope()

    middleware = TrustHandoffMiddleware(
        replay_protection=DummyReplayProtection(),
        max_depth=5,
        revalidate_every_seconds=0.5,
    )

    monkeypatch.setattr(
        "trusthandoff.middleware.within_max_depth",
        lambda chain, max_depth: True,
    )

    class AcceptDecision:
        decision = "ACCEPT"

    monkeypatch.setattr(
        "trusthandoff.middleware.process_handoff",
        lambda packet, audit_collector=None: AcceptDecision(),
    )

    decision, watcher = middleware.handle_with_revalidation(
        envelope,
        revalidate_fn=lambda: True,
    )

    assert decision.decision == "ACCEPT"
    assert isinstance(watcher, RevalidationWatcher)
    watcher.stop()


def test_handle_with_revalidation_returns_none_on_reject(monkeypatch):
    envelope = DummyEnvelope()

    middleware = TrustHandoffMiddleware(
        replay_protection=DummyReplayProtection(),
        max_depth=5,
        revalidate_every_seconds=0.5,
    )

    monkeypatch.setattr(
        "trusthandoff.middleware.within_max_depth",
        lambda chain, max_depth: True,
    )

    class RejectDecision:
        decision = "REJECT"

    monkeypatch.setattr(
        "trusthandoff.middleware.process_handoff",
        lambda packet, audit_collector=None: RejectDecision(),
    )

    decision, watcher = middleware.handle_with_revalidation(
        envelope,
        revalidate_fn=lambda: True,
    )

    assert decision.decision == "REJECT"
    assert watcher is None


def test_handle_with_revalidation_returns_none_when_disabled(monkeypatch):
    envelope = DummyEnvelope()

    middleware = TrustHandoffMiddleware(
        replay_protection=DummyReplayProtection(),
        max_depth=5,
        revalidate_every_seconds=None,
    )

    monkeypatch.setattr(
        "trusthandoff.middleware.within_max_depth",
        lambda chain, max_depth: True,
    )

    class AcceptDecision:
        decision = "ACCEPT"

    monkeypatch.setattr(
        "trusthandoff.middleware.process_handoff",
        lambda packet, audit_collector=None: AcceptDecision(),
    )

    decision, watcher = middleware.handle_with_revalidation(
        envelope,
        revalidate_fn=lambda: True,
    )

    assert decision.decision == "ACCEPT"
    assert watcher is None


def test_handle_with_revalidation_marks_stale(monkeypatch):
    envelope = DummyEnvelope()

    middleware = TrustHandoffMiddleware(
        replay_protection=DummyReplayProtection(),
        max_depth=5,
        revalidate_every_seconds=0.2,
    )

    monkeypatch.setattr(
        "trusthandoff.middleware.within_max_depth",
        lambda chain, max_depth: True,
    )

    class AcceptDecision:
        decision = "ACCEPT"

    monkeypatch.setattr(
        "trusthandoff.middleware.process_handoff",
        lambda packet, audit_collector=None: AcceptDecision(),
    )

    calls = {"ok": True}

    def revalidate():
        return calls["ok"]

    decision, watcher = middleware.handle_with_revalidation(
        envelope,
        revalidate_fn=revalidate,
    )

    assert decision.decision == "ACCEPT"
    assert watcher is not None

    time.sleep(0.25)
    calls["ok"] = False
    time.sleep(0.35)

    assert watcher.state.stale_detected is True
    watcher.stop()
