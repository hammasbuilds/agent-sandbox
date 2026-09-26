#!/usr/bin/env bash
# Run the full chaos/escape suite and the latency benchmark, writing results/*.json.
# Requires a running Docker engine for the default/hardened columns; the subprocess
# column runs regardless. Every container is labelled agent-sandbox=1 and removed with
# --rm; a final cleanup sweep removes any that a crash might have left behind.
set -euo pipefail
cd "$(dirname "$0")/.."

REPS="${REPS:-5}"

echo ">> chaos suite (reps=$REPS)"
uv run agent-sandbox chaos --reps "$REPS" --out results/chaos.json

echo ">> latency benchmark"
uv run agent-sandbox latency --warm 8 --out results/latency.json

echo ">> cleanup"
uv run agent-sandbox cleanup
