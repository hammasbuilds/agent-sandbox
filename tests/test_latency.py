"""Latency design (counterbalancing, pairing, robust statistics), with fakes -- no engine."""

from __future__ import annotations

import random
import statistics

import pytest

from agent_sandbox import latency


def test_orders_are_shuffled_per_round_and_roughly_balanced():
    calls: list[str] = []
    arms = ("a", "b", "c")
    _, orders, _ = latency.run_counterbalanced(
        lambda a: (calls.append(a), 1.0)[1], arms, rounds=300, seed=0, warmup=0
    )
    assert len({tuple(o) for o in orders}) == 6  # every permutation occurs
    counts = latency.position_counts(orders)
    for arm in arms:
        assert sorted(o.index(arm) for o in orders).count(0) == counts[arm][0]
        for c in counts[arm]:
            assert 70 <= c <= 130  # ~100 each: no arm is stuck in one position
    assert len(calls) == 900


def test_warmup_rounds_are_not_counted():
    samples, orders, warm = latency.run_counterbalanced(
        lambda a: 1.0, ("a", "b"), rounds=5, seed=1, warmup=2
    )
    assert [len(v) for v in samples.values()] == [5, 5]
    assert [len(v) for v in warm.values()] == [2, 2]
    assert len(orders) == 5


def test_zero_rounds_rejected():
    with pytest.raises(ValueError):
        latency.run_counterbalanced(lambda a: 1.0, ("a",), rounds=0, seed=0)


def test_paired_analysis_recovers_a_shift_under_drift_and_outliers():
    # Load drifts by up to 20 s between rounds and some rounds are 30 s outliers; `b` is
    # truly 0.5 s slower than `a`. The paired robust estimate must still find ~0.5.
    rng = random.Random(3)
    a, b = [], []
    for i in range(80):
        load = 20 * rng.random() + (30 if i % 17 == 0 else 0)
        noise = lambda: rng.gauss(0, 0.2)  # noqa: E731
        a.append(2.0 + load + noise())
        b.append(2.5 + load + noise())
    res = latency.paired_analysis(b, a)
    lo, hi = res["ci95_s"]
    assert lo <= 0.5 <= hi
    assert abs(res["hodges_lehmann_s"] - 0.5) < 0.15
    assert res["sign_test_p"] < 0.001
    assert res["min_detectable_effect_s"] < 0.2


def test_hodges_lehmann_ci_brackets_the_centre_and_narrows_with_n():
    rng = random.Random(0)
    small = [rng.gauss(1.0, 1.0) for _ in range(20)]
    big = [rng.gauss(1.0, 1.0) for _ in range(400)]
    e1, lo1, hi1 = latency.hodges_lehmann_ci(small)
    e2, lo2, hi2 = latency.hodges_lehmann_ci(big)
    assert lo1 <= e1 <= hi1 and lo2 <= 1.0 <= hi2
    assert (hi2 - lo2) < (hi1 - lo1) / 3


def test_sign_test_exact_values():
    assert latency.sign_test_p([1.0] * 10) == pytest.approx(2 / 2**10)
    assert latency.sign_test_p([1.0, -1.0]) == 1.0
    assert latency.sign_test_p([0.0, 0.0]) == 1.0


def test_mde_and_rounds_needed_are_consistent():
    sd = 3.0
    n = latency.rounds_needed(sd, 1.0)
    assert latency.min_detectable_effect(sd, n) <= 1.0 < latency.min_detectable_effect(sd, n - 1)
    assert latency.robust_sd([1.0, 2.0, 3.0, 4.0, 1000.0]) == pytest.approx(1.4826)


class _NoDocker:
    def docker_available(self) -> bool:
        return False


def test_report_refuses_without_docker():
    with pytest.raises(RuntimeError, match="Docker"):
        latency.build_latency_report(_NoDocker(), rounds=3)  # type: ignore[arg-type]


class _FakeSandbox:
    image = "fake:1"

    def __init__(self) -> None:
        self.preflighted = False
        self.calls = 0

    def docker_available(self) -> bool:
        return True

    def preflight(self) -> None:
        self.preflighted = True


def test_report_preflights_before_timing(monkeypatch):
    sb = _FakeSandbox()

    def fake_one(sandbox, profile):
        assert sandbox.preflighted, "timed a run before the image was pulled and checked"
        sandbox.calls += 1
        return {"subprocess": 0.5, "docker-baseline": 3.0, "hardened": 3.2}[profile]

    monkeypatch.setattr(latency, "_one", fake_one)
    rep = latency.build_latency_report(sb, rounds=6, seed=0)  # type: ignore[arg-type]
    assert sb.calls == 3 * (6 + latency.WARMUP_ROUNDS)
    c = rep["contrasts"]["hardened - docker-baseline"]
    assert c["hodges_lehmann_s"] == pytest.approx(0.2)
    assert statistics.median(rep["profiles"]["subprocess"]["samples_s"]) == 0.5
    assert sum(rep["position_counts"]["hardened"]) == 6
