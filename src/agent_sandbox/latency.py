"""Measure the latency cost of hardening.

Cold start = first container of a profile after nothing is warm (image just resolved,
no cached container state). Warm run = subsequent runs. We report both for the default
and hardened Docker profiles and for the subprocess baseline, so the overhead of adding
the hardening flags is a number, not a guess.
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass
from pathlib import Path

from .runner import Sandbox

TRIVIAL = "print('ok')"


@dataclass
class LatencyStat:
    profile: str
    cold_s: float
    warm_mean_s: float
    warm_median_s: float
    warm_min_s: float
    warm_max_s: float
    n_warm: int
    samples: list[float]

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["samples"] = [round(x, 4) for x in self.samples]
        for k in ("cold_s", "warm_mean_s", "warm_median_s", "warm_min_s", "warm_max_s"):
            d[k] = round(d[k], 4)
        return d


def measure_profile(sandbox: Sandbox, profile: str, n_warm: int = 8) -> LatencyStat:
    samples: list[float] = []
    for _ in range(n_warm + 1):
        t = time.monotonic()
        r = sandbox.run(code=TRIVIAL, profile=profile)
        dt = time.monotonic() - t
        if r.error:
            raise RuntimeError(f"profile {profile} unavailable: {r.error}")
        samples.append(dt)
    cold = samples[0]
    warm = samples[1:]
    return LatencyStat(
        profile=profile,
        cold_s=cold,
        warm_mean_s=statistics.mean(warm),
        warm_median_s=statistics.median(warm),
        warm_min_s=min(warm),
        warm_max_s=max(warm),
        n_warm=len(warm),
        samples=samples,
    )


def build_latency_report(sandbox: Sandbox, n_warm: int = 8) -> dict:
    profiles = ["subprocess"]
    if sandbox.docker_available():
        profiles += ["default", "hardened"]
    stats = [measure_profile(sandbox, p, n_warm=n_warm) for p in profiles]
    by = {s.profile: s for s in stats}
    overhead = None
    if "default" in by and "hardened" in by:
        overhead = {
            "cold_delta_s": round(by["hardened"].cold_s - by["default"].cold_s, 4),
            "warm_delta_s": round(by["hardened"].warm_mean_s - by["default"].warm_mean_s, 4),
            "warm_ratio": round(by["hardened"].warm_mean_s / by["default"].warm_mean_s, 3)
            if by["default"].warm_mean_s
            else None,
        }
    return {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_warm": n_warm,
        "profiles": [s.as_dict() for s in stats],
        "hardening_overhead": overhead,
    }


def write_latency_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
