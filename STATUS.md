# STATUS

**Status: `ENGINEERING-FIXED; CONTAINMENT-RESCORE-PENDING`.** No model arm; nothing is queued
for a GPU run.

An independent review found engineering defects in the sandbox runtime, CLI, latency
benchmark and packaging. All of them are fixed below, each with a regression test. The
containment results (`results/chaos.json`, the 30-attack matrix in the README) are **from the
pre-fix run at commit 4f723dd**. They have not been rerun, and their scoring is pending human
review. No self-score is given until that rerun and review are done; the earlier
"95 / READY-FOR-REVIEW" has been withdrawn.

## What was fixed (runtime, CLI, benchmark, packaging)

| # | Defect | Fix | Regression test |
|---|---|---|---|
| 1 | In-container `timeout` had no kill-after: a SIGTERM-ignoring program ran 44.9 s against a 3 s budget | `timeout -k 2 <wall>` (`docker_cmd.build_exec_argv`) | `test_sigterm_ignoring_program_is_killed_within_budget` (both Docker profiles: exit 137, program time < budget + 2 s + 6 s) |
| 2 | Only `TimeoutExpired` killed the container; Ctrl-C or any other exception leaked it | `except BaseException: kill; raise`, plus `docker rm --force` in `finally`; the same in the streaming helper for the subprocess backend | `test_interrupted_run_leaves_no_container` (real `KeyboardInterrupt` mid-run), `test_keyboard_interrupt_kills_the_process` |
| 3 | Output cap applied after buffering everything (`communicate`/`capture_output`) | `backends/base.run_capped`: 64 KB chunked reads per stream, keep at most `output_bytes`, kill the process/container on overflow, `output_truncated` true only if a stream really passed the cap | `test_capture.py` (both streams, exact-cap case), `test_output_flood_is_capped_and_killed` (subprocess + both Docker profiles) |
| 4 | `/work` was an uncapped host bind mount under `hardened` | `Limits.workspace_bytes` (32 MB for `hardened`): `/work` becomes a size-capped tmpfs; inputs copied in from a read-only `/in` bind; outputs copied out with `tar` via `docker exec`, keeping only regular files with requested names | `test_hardened_workspace_is_size_capped` (ENOSPC at ≤ 32 MB), `test_hardened_files_in_and_out_through_the_tmpfs` (nested paths; symlink and missing file dropped), argv tests |
| 5 | OOM flagged when stderr contained "MemoryError" | Docker's `State.OOMKilled` (container kept until inspected, then removed); subprocess backend reports `None` (not observable). A self-chosen exit 124/137 no longer counts as a timeout unless the program ran for the whole budget | `test_oom_comes_from_docker_state_not_program_output`, `test_program_exiting_124_itself_is_not_a_timeout`, `test_out_of_memory_is_unknown_not_read_from_program_output` |
| 6 | `default` described as "plain docker run, nothing added" | Renamed `docker-baseline` with an accurate description in code, CLI and README; `default` kept as a Python-API alias (one dict entry) | `test_legacy_default_name_is_an_alias`, `test_no_profile_claims_to_be_plain_docker_run` |
| 7 | CLI: `--file-out ../x` traceback; `latency --rounds 0` crash; silent success with Docker down; default outputs overwrote committed `results/` | Clean `agent-sandbox: error:` messages; positive-int validation; `chaos`/`latency`/`cleanup` exit non-zero without Docker (`run` exits 3); default output paths refuse to overwrite without `--out` or `--force` | `test_cli_file_out_escape_is_a_clean_error`, `test_cli_latency_rounds_must_be_positive`, `test_cli_docker_commands_fail_loudly_without_docker`, `test_cli_run_reports_docker_down_with_nonzero_exit`, `test_cli_refuses_to_overwrite_default_results` |
| 8 | Latency: fixed profile order, n=10, bootstrap on a noisy median, stale ablation docstring, first-run pull could be timed | Image pre-pulled and checked, 2 untimed warm-up rounds, per-round shuffled order (seeded, recorded), n=100, Hodges-Lehmann + Wilcoxon-inverted CI + exact sign test + minimum detectable effect; ablation rewritten on the same design with a neutral docstring | `test_latency.py` (balance of positions, drift + outlier recovery, exact sign-test values, MDE consistency, pre-flight before timing, refusal without Docker) |
| 9 | No check that the image has `timeout`; no warning for `--profile subprocess`; `profiles` listed limits not enforced on this OS | `DockerBackend.preflight()` (pull if missing, probe `timeout -k … sleep`, clear `PreflightError`); stderr warning for `subprocess`; `enforced_limits()` drives the listing (subprocess on Windows shows wall + output only) | `test_cli_subprocess_profile_warns`, `test_cli_profiles_lists_only_enforced_limits`, `test_enforced_limits_are_honest_about_the_subprocess_backend` |
| 10 | HostBeacon bound `0.0.0.0` though documented as loopback; stale docstrings; dead code; unformatted files; pytest not installed by `uv sync` | Beacon binds `127.0.0.1` (probe confirmed Docker Desktop still delivers TCP and UDP from `host.docker.internal` to host loopback); docstrings rewritten in `docker_cmd.py`, `subprocess_backend.py`, `runner.py`, `profiles.py`, the HostBeacon part of `attacks/harness.py`; removed `ensure_workdir` and the unused `Backend` protocol; `ruff format` applied; pytest/ruff moved to a `[dependency-groups] dev` group | whole suite; clean-clone check below |
| 11 | *Found during this pass:* a container stopped from outside mid-run (seen once in the first ablation attempt: SIGKILL right after `exec_start`, sender not identifiable from Docker's event log) came back as a normal result with Docker's `cannot exec in a stopped state` as the program's stdout | After the program, the harness reads `State.Running` with `OOMKilled`; a stopped container with no OOM and no harness kill is reported as `error` | `test_container_stopped_from_outside_is_an_error_not_output` |

## Latency (rerun on the fixed runtime)

LATENCY_PLACEHOLDER

## Pending human review (not touched in this pass)

The attack suite (`src/agent_sandbox/attacks/`, `chaos.py`, `scripts/run_chaos.sh`,
`scripts/symlink_ablation.py`, `demo.py`) was deliberately not opened, edited or run in this
pass. The following are open questions about **attack scoring**, for a human to decide
before a rerun:

- **`setuid_escalate`**: whether it should be `n/a`, not "succeeded", when the payload
  already starts as root.
- **`time_bomb`**: its scoring is to be reviewed.
- **Windows-host artefacts** in the matrix (e.g. the subprocess column's `n/a` rows, and the
  symlink attack's unreadable reparse points).
- **Payload-output-based checks**: any check that trusts the program's own stdout/stderr is
  program-controllable (the old OOM flag had this defect).
- **`disk_fill` attribution**: which limit is credited with stopping it under `hardened`
  (read-only rootfs, fsize ulimit, or now the 32 MB tmpfs workspace).
- **Runtime changes the rerun will see**: output-flood runs are now killed at the cap; OOM
  now comes only from Docker; `hardened` file-out now goes through `tar` from a tmpfs (so the
  host-side symlink guard is no longer on that path); orphans are killed by
  `docker rm --force` at the end of the run rather than by PID 1 exiting; the beacon is on
  loopback; results report `docker-baseline` where they used to say `default`. A
  count-only search (the files were not opened) shows `chaos.py` still contains one literal
  `"default"` and resolves profiles and limits through `get_profile`/`limits_for`, which
  accept the alias. `RunResult.profile` now says `docker-baseline`, so any comparison against
  `"default"` in the chaos code has to be checked and renamed in the rescore.
- `ChaosContext.canary_path` / `host_alias` (possibly unread) live in
  `attacks/harness.py`, so they were left alone. `attacks/` and `chaos.py` are excluded from
  `ruff format` for the same reason (`[tool.ruff.format] exclude`).
- `results/chaos.json`, `results/demo_output.txt` (samples 1–2 in the README) and
  `results/symlink_ablation.json` are pre-fix artefacts.

## Reproduce

```bash
uv sync                                    # installs pytest + ruff (dev group)
uv run pytest -q -m "not docker"           # unit suite, no engine needed
uv run pytest -q -m docker --deselect tests/test_docker_integration.py::test_hardened_blocks_key_attacks
                                           # runtime integration tests (the deselected test runs attacks)
uv run agent-sandbox latency --rounds 100 --seed 0 --out results/latency.json
uv run python scripts/latency_ablation.py --rounds 100 --seed 1 --out results/latency_ablation.json
```

`results/cli_samples.txt` holds the `agent-sandbox run …` commands quoted in the README,
rerun on the fixed runtime.

## Known weaknesses remaining

- **Shared host.** Other sessions' jobs ran during the benchmark. The design (warm-up,
  shuffled order, paired robust statistics) is meant to cancel that, and the minimum detectable
  effect is reported, but absolute seconds are specific to this machine.
- **The tmpfs workspace is charged to the memory cgroup.** A `hardened` program that fills
  its 32 MB workspace has only about 96 MB of memory left.
- **The subprocess backend can't observe OOM** and, on Windows, enforces only the wall clock
  and the output cap.
- **A crash of the harness itself** (not an exception, e.g. SIGKILL) leaves the container
  idling on `sleep` until its keep-alive expires. It then stops, and `agent-sandbox cleanup`
  removes it.
