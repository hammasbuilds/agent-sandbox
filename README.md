# agent-sandbox

We built agent-sandbox to run AI-generated code under named hardening profiles and to measure what
each profile actually stops. It runs code as a bare host process, in a Docker container with Docker's
defaults plus safety limits, or in a hardened container, and ships a chaos suite of 30 real attack
programs whose success is judged by the harness from its own evidence. It is for developers who let
an agent execute code and want to know, attack by attack, what their sandbox contains. The package is
pure standard library.

A full web UI for this lives in [LLM Control Room](https://github.com/hammasbuilds/llm-control-room)
(Sandbox page).

## What it does

- **Three profiles:** `subprocess` (the unsafe baseline), `docker-baseline` (Docker defaults with
  host-safety limits) and `hardened` (`--network none`, read-only rootfs, uid 65534, `--cap-drop ALL`,
  `no-new-privileges`, tmpfs workspace, tight memory/pids/cpu/file limits).
- **30 attacks scored by the harness:** network egress (TCP, UDP, HTTP, DNS), secret and host-file
  reads, `/etc/shadow`, root and capability probes, raw sockets, `/proc` and `/sys` leaks, fork, thread,
  memory and disk bombs, time bombs past the timeout, orphan processes and symlink tricks on file-out.
  An attack counts as succeeded only on evidence the harness sees itself: a nonce arriving at a host
  listener, a planted canary found in output, a marker file still changing after the run returned.
- **Budgets enforced inside the container:** `timeout -k 2 <wall>` (SIGTERM, then SIGKILL), output
  streamed with a 1 MB cap per stream, out-of-memory read from Docker's `OOMKilled` state (never from
  program output), and `docker rm --force` in a `finally`.
- **Safe file-in / file-out:** inputs copied in from a read-only bind; outputs copied out with `tar`,
  keeping only regular files with the requested names. The reader refuses symlinks and any path that
  resolves outside the workdir.
- **Paired latency measurement:** profiles interleaved in shuffled order, paired differences with a
  Hodges-Lehmann estimate, Wilcoxon confidence interval and minimum detectable effect.
- **CLI and Python API:** `agent-sandbox run / profiles / chaos / latency / cleanup`, and `Sandbox.run()`.

## Sample input / output

From `uv run python demo.py` (saved in [results/demo_output.txt](results/demo_output.txt)). Ordinary
code with a known answer, the integers `1 2 3 4 5` on stdin summed under `hardened`:

```
profile   : hardened
stdout    : '15'
exit_code : 0
```

Five attacks under three profiles, one repetition each:

```
attack             subprocess     default    hardened
-----------------------------------------------------
env_secret_read     succeeded     blocked     blocked
orphan_survivor     succeeded     blocked     blocked
tcp_egress          succeeded   succeeded     blocked
run_as_root               n/a   succeeded     blocked
memory_bomb         succeeded   succeeded     blocked

Evidence under default:
  tcp_egress        succeeded  beacon received nonce 50789393 (real egress)
  run_as_root       succeeded  process runs as uid 0 (root) inside the container
  memory_bomb       succeeded  memory: reached 300 (>= 200)

Evidence under hardened:
  tcp_egress        blocked    beacon never saw the nonce; program said: FAIL gaierror [Errno -3] Temporary failure in name resolution
  run_as_root       blocked    non-root uid 65534
  memory_bomb       blocked    killed by the memory cgroup (OOM)
```

From the CLI (saved in [results/cli_samples.txt](results/cli_samples.txt)), files in, files out, JSON
result. `scores.csv` held `alice,3 / bob,5 / carol,4`:

```
$ agent-sandbox run --profile hardened --file-in scores.csv --file-out report.txt --json --code "..."
{
  "backend": "docker",
  "profile": "hardened",
  "exit_code": 0,
  "duration_s": 6.157,
  "timed_out": false,
  "out_of_memory": false,
  "output_truncated": false,
  "error": null,
  "stdout": "3 rows\n",
  "stderr": "",
  "files_out": {
    "report.txt": "top=bob total=12\n"
  }
}
```

A runaway loop with a 3-second budget is killed inside the container:

```
$ agent-sandbox run --profile hardened --timeout 3 --code "while True: pass"

[docker/hardened] exit=124 12.91s TIMED_OUT
```

## Results

From [results/chaos.json](results/chaos.json): 30 attacks x 3 profiles x 3 repetitions = 270 runs on
`python:3.12-slim`. Every cell gave the same verdict in all three repetitions and none errored. These
containment runs were made at commit 4f723dd, before the runtime fixes listed in
[docs/RUNTIME_FIXES.md](docs/RUNTIME_FIXES.md); `default` below is the profile now named `docker-baseline`.

| profile | attacks that succeeded |
|---|---|
| `subprocess` (bare host process) | **10 / 14** applicable (16 are Linux-only, n/a on the Windows host) |
| `default` (Docker defaults + safety limits) | **16 / 30** |
| `hardened` | **2 / 30**: `kernel_version_leak`, `mountinfo_leak` |

Plain Docker stopped every host-level attack (host env secret, host file, orphan outliving the run),
but inside the container the code ran as root, reached the network, wrote the root filesystem, opened
raw sockets and ran every resource bomb to its full bounded size. The two attacks that pass `hardened`
read the shared kernel, which no container flag hides.

<details>
<summary>The full 30-attack matrix</summary>

`succeeded` means the sandbox did **not** contain the attack; `n/a` means Linux-only on a Windows host.

| # | attack | subprocess | default | hardened | what closes it |
|---|---|---|---|---|---|
| 1 | `tcp_egress` | **succeeded** | **succeeded** | blocked | `--network none` |
| 2 | `udp_egress` | **succeeded** | **succeeded** | blocked | `--network none` |
| 3 | `http_egress` | **succeeded** | **succeeded** | blocked | `--network none` |
| 4 | `dns_resolve` | **succeeded** | **succeeded** | blocked | `--network none` |
| 5 | `env_secret_read` | **succeeded** | blocked | blocked | any container (fresh env) |
| 6 | `host_canary_read` | **succeeded** | blocked | blocked | any container (mount ns) |
| 7 | `etc_shadow_read` | n/a | **succeeded** | blocked | non-root user |
| 8 | `disk_fill` (40 MB) | **succeeded** | **succeeded** | blocked | read-only rootfs |
| 9 | `symlink_fileout` | blocked | blocked | blocked | harness file-out guard |
| 10 | `rootfs_write` | n/a | **succeeded** | blocked | read-only rootfs |
| 11 | `run_as_root` | n/a | **succeeded** | blocked | `--user 65534` |
| 12 | `setuid_escalate` | n/a | **succeeded** | blocked | non-root + cap-drop |
| 13 | `cap_effective` | n/a | **succeeded** (`0xa80425fb`) | blocked (`0x0`) | `--cap-drop ALL` |
| 14 | `raw_socket` | n/a | **succeeded** | blocked | drops `CAP_NET_RAW` |
| 15 | `mount_syscall` | n/a | blocked | blocked | Docker default |
| 16 | `raise_priority` | n/a | blocked | blocked | Docker default |
| 17 | `kernel_version_leak` | n/a | **succeeded** | **succeeded** | nothing: shared kernel |
| 18 | `mountinfo_leak` | n/a | **succeeded** | **succeeded** | nothing at this layer |
| 19 | `sysrq_trigger` | n/a | blocked | blocked | Docker default (`/proc` ro) |
| 20 | `kcore_read` | n/a | blocked | blocked | Docker default (masked) |
| 21 | `dev_mem` | n/a | blocked | blocked | Docker default (minimal `/dev`) |
| 22 | `docker_socket` | n/a | blocked | blocked | not mounted |
| 23 | `cgroupfs_write` | n/a | blocked | blocked | Docker default (`/sys` ro) |
| 24 | `memory_bomb` (300 MB) | **succeeded** | **succeeded** | blocked (OOM) | `--memory 128m` |
| 25 | `thread_bomb` (200) | **succeeded** | **succeeded** | blocked (at 62) | `--pids-limit 64` |
| 26 | `fork_bomb` (300) | n/a | **succeeded** | blocked (at 62) | `--pids-limit 64` |
| 27 | `cpu_spin` | blocked | blocked | blocked | wall-clock timeout |
| 28 | `time_bomb` | blocked | blocked | blocked | wall-clock timeout |
| 29 | `orphan_survivor` | **succeeded** | blocked | blocked | any container (PID ns) |
| 30 | `output_flood` (~50 MB) | blocked | blocked | blocked | 1 MB output cap |

</details>

**Latency** ([results/latency.json](results/latency.json), 100 rounds, profiles in a shuffled order
each round, paired differences): hardened minus `docker-baseline` was **-0.805 s (Hodges-Lehmann),
95% CI [-1.148, -0.460]**, sign test p = 1.67e-06. Hardening adds no start-up cost; the hardened runs
were slightly faster. The cost is the container itself: medians of 0.375 s for a bare process, 7.203 s
for `docker-baseline` and 6.359 s for `hardened`. A smaller ablation that switched off only the network
([results/latency_ablation.json](results/latency_ablation.json), 15 rounds) could not separate network
setup (+0.016 s, CI [-2.157, +3.625]) from the other flags (+0.296 s, CI [-1.906, +0.969]).

**File-out:** on Linux, a naive reader of a planted `out.txt -> ../canary` symlink returned the canary
(`LINUXCANARY-7f3a`), and the guarded reader returned `{}`
([results/symlink_ablation.json](results/symlink_ablation.json)). File-out happens on the host side of
the mount, so the guard has to live in the harness.

**Tests:** 179 (157 unit tests with fakes, no engine or network; 22 Docker-marked tests that run real
containers and skip when no engine is present).

## Tech stack

- Python 3.11+, standard library only (zero runtime dependencies)
- Docker (for `docker-baseline` and `hardened`), image `python:3.12-slim`
- Dev: pytest, ruff, uv

## Run it

```bash
git clone https://github.com/hammasbuilds/agent-sandbox
cd agent-sandbox
uv sync
uv run python demo.py
uv run agent-sandbox profiles                                   # profiles and limits enforced on this OS
uv run agent-sandbox run --profile hardened --code "print(2 + 2)"   # needs Docker running
uv run agent-sandbox latency --rounds 100 --out my_latency.json
uv run pytest -q -m "not docker"                                # unit tests, no engine needed
```

Commands that need Docker exit non-zero with an `agent-sandbox: error:` line when no engine is
running. `--profile subprocess` warns that the code runs directly on your host; on Windows it enforces
only the wall clock and the output cap. Any image works if it has `python`, `sleep`, `tar`, `cp`, `sh`
and a `timeout` that supports `-k`. For untrusted code in production, put a kernel boundary (gVisor or a
microVM) under the hardened profile: every profile here shares the host kernel.

```python
from agent_sandbox import Sandbox

r = Sandbox().run(
    code="import sys; print(sum(int(x) for x in sys.stdin.read().split()))",
    profile="hardened",
    stdin="1 2 3 4 5",
)
print(r.stdout, r.exit_code, r.duration_s)
```

Code layout: `src/agent_sandbox/profiles.py` (the three profiles), `runner.py` (backend choice and
limits), `backends/` (Docker argv builders, Docker backend, subprocess baseline, capped output and the
file-out guard), `attacks/` (beacon, the 30 attacks and their harness-side checks), `chaos.py`,
`latency.py`, `cli.py`; `scripts/` reproduces the chaos run and both ablations; `results/` holds every
number above.

## Licence

MIT, see [LICENSE](LICENSE). Inspired by [daytonaio/daytona](https://github.com/daytonaio/daytona); no
code from it is used.
