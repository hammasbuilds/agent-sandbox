"""Latency design (interleaving + pairing) and orphan helpers, with fakes -- no engine."""

from __future__ import annotations

from agent_sandbox import latency
from agent_sandbox.chaos import _container_name, _verdict
from agent_sandbox.types import RunResult


class FakeSandbox:
    """Records call order; each profile has a fixed cost plus a shared, drifting load."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.load = 0.0

    def docker_available(self) -> bool:
        return True

    def run(self, *, code: str, profile: str) -> RunResult:
        self.calls.append(profile)
        return RunResult("fake", profile, 0, "ok\n", "", 0.0, False)


def test_profiles_are_interleaved(monkeypatch):
    sb = FakeSandbox()
    monkeypatch.setattr(latency, "_one", lambda s, p: (sb.calls.append(p), 1.0)[1])
    latency.build_latency_report(sb, rounds=3)
    assert sb.calls[:6] == ["subprocess", "default", "hardened"] * 2


def test_paired_difference_cancels_shared_drift(monkeypatch):
    # Load drifts upward by 10s every round; hardened is truly 0.5s slower than default.
    state = {"round_load": 0.0, "n": 0}
    cost = {"subprocess": 1.0, "default": 2.0, "hardened": 2.5}

    def fake_one(sandbox, profile):
        if profile == "subprocess":
            state["round_load"] = 10.0 * state["n"]
            state["n"] += 1
        return cost[profile] + state["round_load"]

    monkeypatch.setattr(latency, "_one", fake_one)
    rep = latency.build_latency_report(FakeSandbox(), rounds=8)
    ov = rep["hardening_overhead"]
    assert ov["paired_diff_median_s"] == 0.5
    assert ov["hardened_slower_in_rounds"] == 8
    lo, hi = ov["paired_diff_ci95_s"]
    assert lo <= 0.5 <= hi


def test_bootstrap_ci_brackets_median():
    lo, hi = latency._bootstrap_ci([1.0, 2.0, 3.0, 4.0, 5.0])
    assert lo <= 3.0 <= hi


def test_container_name_extracted_from_argv():
    argv = ("docker", "run", "--rm", "--name", "agsbx-abc123", "img", "python")
    assert _container_name(argv) == "agsbx-abc123"
    assert _container_name(("docker", "run")) is None


def test_verdict_any_breach_wins():
    assert _verdict({"succeeded": 1, "blocked": 2, "n/a": 0, "error": 0}, 3) == "succeeded"
    assert _verdict({"succeeded": 0, "blocked": 3, "n/a": 0, "error": 0}, 3) == "blocked"
    assert _verdict({"succeeded": 0, "blocked": 0, "n/a": 3, "error": 0}, 3) == "n/a"
    assert _verdict({"succeeded": 0, "blocked": 0, "n/a": 0, "error": 3}, 3) == "error"
