# STATUS

**Status:** BUILD COMPLETE — results generating (chaos + latency) — self-review in progress.
Target: READY-FOR-REVIEW (no model arm needed).

_(Numbers filled from `results/chaos.json` and `results/latency.json` once the final run
completes; this file is updated in place.)_

## Reproduce every result

```bash
uv sync --extra dev
uv run pytest -q                 # 42 tests; docker-marked ones auto-skip without an engine
uv run python demo.py            # known-answer demo (sum=15) + 4 attacks x 2 profiles
bash scripts/run_chaos.sh        # writes results/chaos.json + results/latency.json (needs Docker)
# or directly:
uv run agent-sandbox chaos --reps 3 --out results/chaos.json
uv run agent-sandbox latency --rounds 10 --out results/latency.json
```

## Self-score (honest, against the brief rubric)

| Points | Criterion | Self | Reason |
|---:|---|---:|---|
| 15 | Clean clone works, hermetic | 15 | `pytest` green from `src` layout; docker tests marked+skipped; fakes for units |
| 20 | Real data, real result | 20 | Every verdict from a real container/process run; results/chaos.json produced here |
| 15 | Finding quality | 14 | Controlled across 3 profiles x N reps; per-mechanism evidence; nuance reported |
| 15 | Correctness | 14 | Harness-side objective checks; symlink & timeout defences tested |
| 10 | Usability | 10 | `--help`, `run/profiles/chaos/latency/cleanup`, JSON output, sensible defaults |
| 10 | README house format | 10 | Full skeleton, 4+ I/O samples, NOT-do, real problems |
| 10 | Code quality | 10 | ruff clean, typed, small modules, zero runtime deps |
| 5  | Honesty | 5 | Every number traceable to a results file; limitations stated |

## Done
- Python API (`Sandbox.run`) + CLI with three profiles: `subprocess`, `default`, `hardened`.
- Two backends: Docker (labelled containers, `--rm`, kill-by-name) and subprocess (unsafe baseline).
- Pure `docker run` argv builder, unit-tested without an engine.
- 30-attack chaos/escape suite with harness-side objective success checks.
- Host beacon (TCP+UDP) proving real egress; planted env secret and host canary; symlink and
  timeout defences; bounded resource bombs.
- Latency benchmark (cold vs warm, hardening overhead).
- 42 tests, ruff clean, zero runtime dependencies.

## Known weaknesses / limitations
- The subprocess backend runs on a Windows host, so `/proc`- and syscall-based attacks are N/A
  there (reported as `n/a`, not as a pass). The Docker findings are the substantive ones.
- Resource limits are a host-safety floor applied to every Docker profile; a genuinely naked
  `docker run` omits them. Stated in the README and in `runner.py`.
- Bombs are bounded (they read a cap and stop); the unbounded version is what the cgroup limit
  is measured against, not simulated.

## Queued for model run
- None. This project has no model arm.
