"""Ablation: how much of the hardened-vs-baseline start-up difference is network setup?

`docker-baseline` attaches a bridge network (a veth pair, NAT rules) at container start;
`hardened` uses `--network none`, which skips it. Two control arms switch ONLY the network:
`baseline-nonet` is docker-baseline with `--network none`, and `hardened-bridge` is hardened
with the bridge network. That measures the network's cost twice, once against each
profile's other flags, and splits the total hardened - baseline difference into the network
part and the part due to every other hardening flag and limit (including the tmpfs
workspace copy-in).

Same design as `agent-sandbox latency`: image pre-pulled and checked, untimed warm-up,
per-round shuffled order, paired Hodges-Lehmann estimates with Wilcoxon 95% CIs and the
minimum detectable effect.

Run:  uv run python scripts/latency_ablation.py --rounds 100 --out results/latency_ablation.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import replace
from pathlib import Path

from agent_sandbox.backends.docker import DockerBackend
from agent_sandbox.latency import (
    WARMUP_ROUNDS,
    paired_analysis,
    position_counts,
    run_counterbalanced,
)
from agent_sandbox.profiles import DOCKER_BASELINE, HARDENED, Profile
from agent_sandbox.runner import limits_for
from agent_sandbox.types import RunSpec

NO_NET = replace(DOCKER_BASELINE, name="baseline-nonet", network="none")
HARD_BRIDGE = replace(HARDENED, name="hardened-bridge", network="bridge")
ARMS: dict[str, tuple[Profile, str]] = {
    "docker-baseline": (DOCKER_BASELINE, "docker-baseline"),
    "baseline-nonet": (NO_NET, "docker-baseline"),
    "hardened": (HARDENED, "hardened"),
    "hardened-bridge": (HARD_BRIDGE, "hardened"),
}
# (label, a, b): each contrast is a - b per round.
CONTRASTS = (
    ("docker-baseline - baseline-nonet (bridge network, baseline flags)", "docker-baseline",
     "baseline-nonet"),
    ("hardened-bridge - hardened (bridge network, hardened flags)", "hardened-bridge", "hardened"),
    ("hardened - baseline-nonet (other hardening flags + tmpfs workspace, no network)",
     "hardened", "baseline-nonet"),
    ("hardened - docker-baseline (total)", "hardened", "docker-baseline"),
)  # fmt: skip
DEFAULT_OUT = "results/latency_ablation.json"


def _time(backend: DockerBackend, arm: str) -> float:
    profile, limits_name = ARMS[arm]
    spec = RunSpec(code="print('ok')", limits=limits_for(limits_name))
    t = time.monotonic()
    r = backend.run(spec, profile)
    dt = time.monotonic() - t
    if r.error or r.stdout.strip() != "ok":
        raise RuntimeError(f"{arm}: {r.error or 'unexpected output'} {r.stdout!r} {r.stderr!r}")
    return dt


def main() -> None:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--rounds", type=int, default=100)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=None, help=f"output path (default: {DEFAULT_OUT})")
    ap.add_argument("--force", action="store_true", help="overwrite the default output file")
    args = ap.parse_args()
    if args.rounds < 1:
        raise SystemExit("--rounds must be at least 1")
    out = Path(args.out or DEFAULT_OUT)
    if args.out is None and out.exists() and not args.force:
        raise SystemExit(f"{out} already exists; pass --out PATH or --force")

    backend = DockerBackend()
    if not backend.available():
        raise SystemExit("error: the ablation needs a running Docker engine")
    backend.preflight()
    try:
        samples, orders, warm = run_counterbalanced(
            lambda arm: _time(backend, arm), tuple(ARMS), rounds=args.rounds, seed=args.seed
        )
    finally:
        backend.cleanup()  # this run's session only
    report = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rounds": args.rounds,
        "seed": args.seed,
        "position_counts": position_counts(orders),
        "image": backend.image,
        "design": (
            f"image pre-pulled and checked; {WARMUP_ROUNDS} untimed warm-up rounds; "
            f"{args.rounds} measured rounds, each arm once per round in a per-round shuffled "
            f"order (seed {args.seed}); paired per-round differences; Hodges-Lehmann estimate "
            "with Wilcoxon-inverted 95% CI, exact sign test, MDE at 80% power"
        ),
        "median_s": {k: round(statistics.median(v), 3) for k, v in samples.items()},
        "paired": {label: paired_analysis(samples[a], samples[b]) for label, a, b in CONTRASTS},
        "warmup_s": {k: [round(x, 3) for x in v] for k, v in warm.items()},
        "samples_s": {k: [round(x, 3) for x in v] for k, v in samples.items()},
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    print("medians:", report["median_s"])
    for k, v in report["paired"].items():
        lo, hi = v["ci95_s"]
        print(
            f"  {k}: HL {v['hodges_lehmann_s']:+}s [95% CI {lo:+}, {hi:+}] "
            f"({v['first_slower_in_rounds']}/{v['rounds']}), MDE {v['min_detectable_effect_s']}s"
        )


if __name__ == "__main__":
    main()
