#!/usr/bin/env bash
# Regenerate every committed result: the chaos matrix, the latency benchmark and its
# ablation, the symlink ablation and the demo output. Needs a running Docker engine.
#
# Every container is labelled agent-sandbox=1 plus a per-process session label, and each
# run's container is removed with `docker rm --force` when the run ends (in a `finally`).
# The final sweep removes only containers that have already stopped, so it never touches
# a run in progress in another process.
set -euo pipefail
cd "$(dirname "$0")/.."

REPS="${REPS:-3}"
ROUNDS="${ROUNDS:-100}"

echo ">> chaos suite (reps=$REPS)"
uv run agent-sandbox chaos --reps "$REPS" --out results/chaos.json

echo ">> latency benchmark (rounds=$ROUNDS)"
uv run agent-sandbox latency --rounds "$ROUNDS" --seed 0 --out results/latency.json

echo ">> latency ablation (rounds=$ROUNDS)"
uv run python scripts/latency_ablation.py --rounds "$ROUNDS" --seed 1 --out results/latency_ablation.json

echo ">> symlink ablation"
uv run python scripts/symlink_ablation.py --out results/symlink_ablation.json

echo ">> demo"
uv run python demo.py > results/demo_output.txt

echo ">> sweep stopped leftovers"
uv run agent-sandbox cleanup
