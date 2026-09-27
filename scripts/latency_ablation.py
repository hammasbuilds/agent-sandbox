"""Ablation: why is `hardened` faster to start than `default`?

Hypothesis: the difference is network setup. `default` attaches a bridge network (a veth
pair, NAT rules) at container start; `hardened` uses `--network none`, which skips it.
Control: `default` with ONLY the network switched off (`default-nonet`). If the hypothesis
holds, `default-nonet` should start about as fast as `hardened`, and the remaining
hardening flags (read-only rootfs, non-root, cap-drop, no-new-privileges, limits) should cost
~nothing.

Interleaved round-robin, round 0 dropped, paired per-round differences with a bootstrap CI.
Writes results/latency_ablation.json.

Run:  uv run python scripts/latency_ablation.py --rounds 15
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import replace
from pathlib import Path

from agent_sandbox.backends.docker import DockerBackend
from agent_sandbox.latency import _bootstrap_ci
from agent_sandbox.profiles import DEFAULT, HARDENED
from agent_sandbox.runner import limits_for
from agent_sandbox.types import RunSpec

ARMS = {
    "default": (DEFAULT, "default"),
    "default-nonet": (replace(DEFAULT, name="default-nonet", network="none"), "default"),
    "hardened": (HARDENED, "hardened"),
}


def _time(backend: DockerBackend, profile, limits_name: str) -> float:
    spec = RunSpec(code="print('ok')", limits=limits_for(limits_name))
    t = time.monotonic()
    r = backend.run(spec, profile)
    dt = time.monotonic() - t
    if r.stdout.strip() != "ok":
        raise RuntimeError(f"{profile.name}: unexpected output {r.stdout!r} {r.stderr!r}")
    return dt


def _paired(a: list[float], b: list[float]) -> dict:
    d = [x - y for x, y in zip(a, b, strict=True)]
    lo, hi = _bootstrap_ci(d)
    return {
        "median_s": round(statistics.median(d), 3),
        "ci95_s": [round(lo, 3), round(hi, 3)],
        "first_slower_in_rounds": sum(1 for x in d if x > 0),
        "rounds": len(d),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rounds", type=int, default=15)
    ap.add_argument("--out", default="results/latency_ablation.json")
    args = ap.parse_args()

    backend = DockerBackend()
    if not backend.available():
        raise SystemExit("Docker engine not available")
    samples: dict[str, list[float]] = {k: [] for k in ARMS}
    for _ in range(args.rounds + 1):
        for name, (prof, lim) in ARMS.items():
            samples[name].append(_time(backend, prof, lim))
    s = {k: v[1:] for k, v in samples.items()}  # drop round 0

    report = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rounds": args.rounds,
        "median_s": {k: round(statistics.median(v), 3) for k, v in s.items()},
        "paired": {
            "default_minus_default-nonet (network setup)": _paired(
                s["default"], s["default-nonet"]
            ),
            "hardened_minus_default-nonet (remaining hardening flags)": _paired(
                s["hardened"], s["default-nonet"]
            ),
            "hardened_minus_default (total)": _paired(s["hardened"], s["default"]),
        },
        "samples_s": {k: [round(x, 3) for x in v] for k, v in samples.items()},
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    print("medians:", report["median_s"])
    for k, v in report["paired"].items():
        slower = f"{v['first_slower_in_rounds']}/{v['rounds']}"
        print(f"  {k}: {v['median_s']}s CI{v['ci95_s']} ({slower})")


if __name__ == "__main__":
    main()
