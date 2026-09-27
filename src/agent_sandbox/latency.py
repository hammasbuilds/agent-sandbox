"""Measure the latency cost of hardening, controlled for host-load drift.

Profiles are measured *interleaved*, round-robin (subprocess, default, hardened, then
again), rather than one block after another. On a shared host the background load drifts
by tens of seconds over a benchmark; measuring profiles in sequence would attribute that
drift to whichever profile happened to run during the busy stretch. Interleaving puts every
profile under the same load in each round, and the per-round *paired* difference
(hardened minus default) cancels most of it.

Round 0 is reported as "first run" rather than a true cold start: both Docker profiles
share one image, so only the very first container in the process is genuinely cold.
"""

from __future__ import annotations

import json
import random
import statistics
import time
from pathlib import Path

from .runner import Sandbox

TRIVIAL = "print('ok')"


def _one(sandbox: Sandbox, profile: str) -> float:
    t = time.monotonic()
    r = sandbox.run(code=TRIVIAL, profile=profile)
    dt = time.monotonic() - t
    if r.error:
        raise RuntimeError(f"profile {profile} unavailable: {r.error}")
    if r.stdout.strip() != "ok":
        raise RuntimeError(f"profile {profile} produced unexpected output: {r.stdout!r}")
    return dt


def _bootstrap_ci(values: list[float], iters: int = 5000, seed: int = 0) -> tuple[float, float]:
    """95% percentile-bootstrap CI of the median."""
    rng = random.Random(seed)
    meds = sorted(
        statistics.median(rng.choices(values, k=len(values))) for _ in range(iters)
    )
    return meds[int(0.025 * iters)], meds[int(0.975 * iters) - 1]


def _summ(samples: list[float]) -> dict:
    return {
        "first_run_s": round(samples[0], 3),
        "median_s": round(statistics.median(samples[1:]), 3),
        "min_s": round(min(samples[1:]), 3),
        "max_s": round(max(samples[1:]), 3),
        "n": len(samples) - 1,
        "samples_s": [round(x, 3) for x in samples],
    }


def build_latency_report(sandbox: Sandbox, rounds: int = 10) -> dict:
    profiles = ["subprocess"]
    if sandbox.docker_available():
        profiles += ["default", "hardened"]

    samples: dict[str, list[float]] = {p: [] for p in profiles}
    for _ in range(rounds + 1):  # round 0 = first run, excluded from the stats
        for p in profiles:
            samples[p].append(_one(sandbox, p))

    report: dict = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "design": "interleaved round-robin; round 0 excluded; paired per-round differences",
        "rounds": rounds,
        "profiles": {p: _summ(s) for p, s in samples.items()},
        "hardening_overhead": None,
    }
    if "default" in samples:
        pairs = zip(samples["hardened"][1:], samples["default"][1:], strict=True)
        diffs = [h - d for h, d in pairs]
        lo, hi = _bootstrap_ci(diffs)
        report["hardening_overhead"] = {
            "paired_diff_median_s": round(statistics.median(diffs), 3),
            "paired_diff_ci95_s": [round(lo, 3), round(hi, 3)],
            "hardened_slower_in_rounds": sum(1 for x in diffs if x > 0),
            "rounds": len(diffs),
            "paired_diffs_s": [round(x, 3) for x in diffs],
        }
    return report


def write_latency_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
