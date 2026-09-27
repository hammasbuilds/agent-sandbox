# STATUS

**Status: READY-FOR-REVIEW.** No model arm; nothing queued for a GPU run. Self-score **95/100**.

## Headline (from `results/chaos.json`, 30 attacks × 3 profiles × 3 reps, every cell unanimous)

| profile | attacks that succeeded |
|---|---|
| `subprocess` (bare host process) | 10 / 14 applicable (16 Linux-only attacks are n/a on the Windows host) |
| `default` (plain `docker run`) | 16 / 30 |
| `hardened` | 2 / 30 — both are reads of the shared kernel (`/proc/version`, `/proc/self/mountinfo`) |

The hypothesis "Docker by itself is a sandbox" is **half wrong**. Plain Docker stopped every
host-reaching attack (host env secret, host file, orphan process). But inside the container the
code ran as root, kept capabilities `0xa80425fb`, reached the network over TCP/UDP/HTTP/DNS,
wrote `/etc`, read `/etc/shadow`, opened raw sockets and ran every bounded resource bomb to its
full size. Hardening closed all of those.

Latency (`results/latency.json`, `results/latency_ablation.json`; interleaved, paired, bootstrap
CI): hardened − default = −0.99 s, 95% CI [−4.80, +1.86]. Network setup costs +0.02 s
[−2.16, +3.63]; the other hardening flags cost +0.30 s [−1.91, +0.97]. **Hardening adds no
measurable start-up cost at this host's noise level.**

## Reproduce every result

```bash
uv sync --extra dev
uv run pytest -q                                   # 64 tests (56 unit + 8 docker-marked)
uv run python demo.py                              # -> results/demo_output.txt
uv run agent-sandbox chaos --reps 3 --out results/chaos.json
uv run agent-sandbox latency --rounds 10 --out results/latency.json
uv run python scripts/latency_ablation.py --rounds 15   # -> results/latency_ablation.json
uv run python scripts/symlink_ablation.py               # -> results/symlink_ablation.json
# results/cli_samples.txt: the three `agent-sandbox run ...` commands printed in it
bash scripts/run_chaos.sh                          # chaos + latency + cleanup in one go
```

Needs Docker running and `python:3.12-slim`. The chaos run took about 30 min on this
(heavily shared) machine.

## Self-score

| Pts | Criterion | Self | Reason |
|---:|---|---:|---|
| 15 | Clean clone, hermetic | 15 | Fresh clone: `uv sync` → 64 pass, ruff clean, demo reproduces. With `docker` removed from PATH: 56 pass, 8 skip. With HOME/TEMP pointed at an empty dir: unit suite passes. |
| 20 | Real data, real result | 19 | 270 real container/process runs; host-observed evidence (beacon nonces, planted tokens, container liveness). −1: the subprocess column covers only 14/30 attacks because the host is Windows. |
| 15 | Finding quality | 14 | 3 profiles × 3 reps, all unanimous; ablations for the symlink guard (naive vs guarded, Windows + Linux) and for latency (network on/off); bootstrap CIs; 5 surprising numbers investigated and fixed (see README). −1: n=3 reps per cell and one image/kernel. |
| 15 | Correctness | 14 | Checks never trust the attacker's claim; false breaches (kcore, pid1 self-read) and a false block (orphan) found and fixed; limit and path validation. −1: default profile carries a host-safety resource floor, so "default" is not a literally naked `docker run` (stated). |
| 10 | Usability | 10 | `run` (code/file, stdin, env, file-in/out, timeout, JSON), `profiles`, `chaos`, `latency`, `cleanup`; clear errors for bad timeout, missing file, bad env, escaping paths. |
| 10 | README | 10 | House skeleton, full 30-row matrix, 5 real I/O samples, NOT-do, 9 real problems. |
| 10 | Code quality | 10 | ruff clean, typed, small modules, zero runtime deps, no dead code. |
| 5 | Honesty | 5 | Every README number traced to `results/*`; latency reported as "no measurable difference" rather than the favourable earlier point estimate. |
| | **Total** | **97 → scored 95** | Rounded down for the shared-host noise on latency and the Windows-host subprocess gap. |

## Done
- Python API + CLI; three profiles; Docker backend (labelled containers, `--rm`, kill-by-name,
  in-container `timeout`, `--interactive` stdin, cached engine probe) and subprocess baseline.
- 30-attack suite with harness-side checks; host TCP/UDP beacon; bounded bombs; symlink-safe file-out.
- Interleaved, paired latency benchmark + network ablation; symlink guard ablation incl. Linux run.
- 64 tests; ruff clean; results, demo and CLI output committed.

## Known weaknesses remaining
- **Shared, overloaded host.** Other sessions' training jobs ran throughout: Docker start-up
  ranged from about 3.5 s to 28 s, so the absolute latencies are not representative. Only the
  paired differences should be read, and they are noise-limited (CIs about ±3 s).
- **Subprocess baseline on Windows.** 16 `/proc`/syscall attacks are n/a there. A Linux host
  would complete that column.
- **One image, one kernel (WSL2 6.18), Docker's default seccomp.** Not tested: gVisor, rootless
  Docker, user namespaces, AppArmor/SELinux.
- **`default` has a host-safety floor** (512 MB, 512 pids, 64 MB fsize) so bombs can't hurt the
  test machine. The bombs are bounded below it.
- **Symlink guard, Windows side.** On this host the guard is never actually exercised by the
  chaos run: Windows can't read Linux symlinks on bind mounts. It is proven by the Linux
  simulation and a Docker-marked test.

## Queued for model run
None — this project has no model arm.

## Blockers hit
- PyPI throttled at first; a later `uv sync` in a clean clone succeeded in about 90 s.
- Docker Desktop was slow or intermittently unresponsive under other sessions' load. Every
  Docker-dependent step was made robust to it rather than retried until it looked good.
