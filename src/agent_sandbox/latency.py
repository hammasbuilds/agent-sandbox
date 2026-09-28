"""Measure the latency cost of each profile, controlled for host-load drift.

Design:

* **Pre-flight and warm-up, untimed.** The image is pulled if missing and checked before
  anything is timed, then every profile runs ``WARMUP_ROUNDS`` untimed rounds, so neither a
  first-run pull nor a cold cache lands in the numbers.
* **Counterbalanced order.** Every profile runs once per round, in an order shuffled
  independently each round from a seeded RNG (recorded in the report). A fixed order would
  let a systematic position effect -- e.g. the second container of a round reusing warm
  state from the first -- masquerade as a profile effect.
* **Paired, robust analysis.** On a shared host the load drifts by seconds, so each
  contrast is analysed as per-round paired differences. The estimate is the
  Hodges-Lehmann median of Walsh averages, with the distribution-free 95% CI obtained by
  inverting the Wilcoxon signed-rank test, and an exact two-sided sign-test p-value. None of
  these assume normality or are moved much by the heavy tail of slow rounds.
* **Stated resolution.** Each contrast reports its minimum detectable effect (80% power,
  two-sided alpha 0.05) from a robust spread estimate (1.4826 x MAD of the paired
  differences), so "no difference" can be read as "no difference larger than X".
"""

from __future__ import annotations

import json
import math
import random
import statistics
import time
from collections.abc import Callable
from pathlib import Path

from .runner import Sandbox

TRIVIAL = "print('ok')"
PROFILES = ("subprocess", "docker-baseline", "hardened")
WARMUP_ROUNDS = 2
# (label, a, b): each contrast is a - b per round.
CONTRASTS = (
    ("hardened - docker-baseline", "hardened", "docker-baseline"),
    ("docker-baseline - subprocess", "docker-baseline", "subprocess"),
)
_Z975 = 1.959963984540054
_Z80 = 0.8416212335729143
_WILCOXON_ARE = 3 / math.pi  # asymptotic efficiency of Wilcoxon vs the t-test under normality


def _one(sandbox: Sandbox, profile: str) -> float:
    t = time.monotonic()
    r = sandbox.run(code=TRIVIAL, profile=profile)
    dt = time.monotonic() - t
    if r.error:
        raise RuntimeError(f"profile {profile} failed: {r.error}")
    if r.stdout.strip() != "ok":
        raise RuntimeError(f"profile {profile} produced unexpected output: {r.stdout!r}")
    return dt


def hodges_lehmann_ci(diffs: list[float], z: float = _Z975) -> tuple[float, float, float]:
    """Hodges-Lehmann estimate and Wilcoxon-inverted CI (normal approximation) of the
    location of paired differences. Returns (estimate, low, high)."""
    n = len(diffs)
    if n == 0:
        raise ValueError("need at least one paired difference")
    walsh = sorted((diffs[i] + diffs[j]) / 2 for i in range(n) for j in range(i, n))
    est = statistics.median(walsh)
    m = len(walsh)
    k = math.floor(n * (n + 1) / 4 - z * math.sqrt(n * (n + 1) * (2 * n + 1) / 24))
    k = max(0, min(k, (m - 1) // 2))
    return est, walsh[k], walsh[m - 1 - k]


def sign_test_p(diffs: list[float]) -> float:
    """Exact two-sided sign-test p-value; zero differences are dropped."""
    pos = sum(1 for d in diffs if d > 0)
    neg = sum(1 for d in diffs if d < 0)
    n = pos + neg
    if n == 0:
        return 1.0
    k = min(pos, neg)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2**n
    return min(1.0, 2 * tail)


def robust_sd(values: list[float]) -> float:
    """1.4826 x median absolute deviation: a spread estimate a few outliers cannot inflate."""
    med = statistics.median(values)
    return 1.4826 * statistics.median(abs(v - med) for v in values)


def min_detectable_effect(sd: float, n: int) -> float:
    """Smallest true shift detectable with 80% power at two-sided alpha 0.05 (Wilcoxon)."""
    return (_Z975 + _Z80) * sd / math.sqrt(_WILCOXON_ARE * n)


def rounds_needed(sd: float, effect: float) -> int:
    """Rounds needed for ``min_detectable_effect`` to reach ``effect``."""
    return math.ceil(((_Z975 + _Z80) * sd / effect) ** 2 / _WILCOXON_ARE)


def paired_analysis(a: list[float], b: list[float]) -> dict:
    diffs = [x - y for x, y in zip(a, b, strict=True)]
    est, lo, hi = hodges_lehmann_ci(diffs)
    sd = robust_sd(diffs)
    return {
        "hodges_lehmann_s": round(est, 3),
        "ci95_s": [round(lo, 3), round(hi, 3)],
        "median_diff_s": round(statistics.median(diffs), 3),
        "first_slower_in_rounds": sum(1 for d in diffs if d > 0),
        "rounds": len(diffs),
        "sign_test_p": float(f"{sign_test_p(diffs):.3g}"),  # 3 significant figures
        "robust_sd_s": round(sd, 3),
        "min_detectable_effect_s": round(min_detectable_effect(sd, len(diffs)), 3),
        "rounds_needed_for_1s_mde": rounds_needed(sd, 1.0) if sd > 0 else 1,
        "paired_diffs_s": [round(d, 3) for d in diffs],
    }


def _summ(samples: list[float]) -> dict:
    q = statistics.quantiles(samples, n=4) if len(samples) > 1 else [samples[0]] * 3
    return {
        "median_s": round(statistics.median(samples), 3),
        "q1_s": round(q[0], 3),
        "q3_s": round(q[2], 3),
        "min_s": round(min(samples), 3),
        "max_s": round(max(samples), 3),
        "n": len(samples),
        "samples_s": [round(x, 3) for x in samples],
    }


def run_counterbalanced(
    measure: Callable[[str], float],
    arms: tuple[str, ...],
    rounds: int,
    seed: int,
    warmup: int = WARMUP_ROUNDS,
) -> tuple[dict[str, list[float]], list[list[str]], dict[str, list[float]]]:
    """Time every arm once per round in a freshly shuffled order.

    Returns (samples per arm, the order used in each measured round, warm-up samples).
    """
    if rounds < 1:
        raise ValueError(f"rounds must be >= 1, got {rounds}")
    rng = random.Random(seed)
    warm: dict[str, list[float]] = {a: [] for a in arms}
    for _ in range(warmup):
        for a in arms:
            warm[a].append(measure(a))
    samples: dict[str, list[float]] = {a: [] for a in arms}
    orders: list[list[str]] = []
    for _ in range(rounds):
        order = list(arms)
        rng.shuffle(order)
        orders.append(order)
        for a in order:
            samples[a].append(measure(a))
    return samples, orders, warm


def position_counts(orders: list[list[str]]) -> dict[str, list[int]]:
    """How often each arm ran in each position (a check that the order was balanced)."""
    arms = sorted({a for o in orders for a in o})
    width = max((len(o) for o in orders), default=0)
    counts = {a: [0] * width for a in arms}
    for o in orders:
        for i, a in enumerate(o):
            counts[a][i] += 1
    return counts


def build_latency_report(sandbox: Sandbox, rounds: int = 100, seed: int = 0) -> dict:
    if not sandbox.docker_available():
        raise RuntimeError("the latency benchmark needs a running Docker engine")
    sandbox.preflight()  # pull + check the image before anything is timed

    samples, orders, warm = run_counterbalanced(
        lambda p: _one(sandbox, p), PROFILES, rounds=rounds, seed=seed
    )
    return {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "image": sandbox.image,
        "design": (
            f"image pre-pulled and checked; {WARMUP_ROUNDS} untimed warm-up rounds; "
            f"{rounds} measured rounds, each profile once per round in a per-round shuffled "
            f"order (seed {seed}); paired per-round differences; Hodges-Lehmann estimate "
            "with Wilcoxon-inverted 95% CI, exact sign test, MDE at 80% power"
        ),
        "rounds": rounds,
        "seed": seed,
        "position_counts": position_counts(orders),
        "orders": orders,
        "warmup_s": {p: [round(x, 3) for x in v] for p, v in warm.items()},
        "profiles": {p: _summ(s) for p, s in samples.items()},
        "contrasts": {label: paired_analysis(samples[a], samples[b]) for label, a, b in CONTRASTS},
    }


def format_latency_report(report: dict) -> str:
    lines = []
    for name, s in report["profiles"].items():
        lines.append(
            f"  {name:15s} median={s['median_s']}s IQR=[{s['q1_s']}, {s['q3_s']}] "
            f"min={s['min_s']}s max={s['max_s']}s n={s['n']}"
        )
    for label, c in report["contrasts"].items():
        lo, hi = c["ci95_s"]
        lines.append(
            f"  {label}: HL {c['hodges_lehmann_s']:+}s [95% CI {lo:+}, {hi:+}], "
            f"first slower in {c['first_slower_in_rounds']}/{c['rounds']} rounds, "
            f"sign-test p={c['sign_test_p']}, MDE {c['min_detectable_effect_s']}s"
        )
    return "\n".join(lines)


def write_latency_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
