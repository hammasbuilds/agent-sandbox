<h1 align="center">agent-sandbox (Docker · cgroups · seccomp · Python)</h1>
<p align="center"><i>Run AI-generated code under named hardening profiles, then measure what each profile actually stops</i></p>

<p align="center">
  <a href="#the-through-line">The through-line</a> &middot;
  <a href="#findings">Findings</a> &middot;
  <a href="#profiles">Profiles</a> &middot;
  <a href="#input--output">Input / Output</a> &middot;
  <a href="#quick-start">Quick start</a> &middot;
  <a href="#what-this-does-not-do">What it does NOT do</a> &middot;
  <a href="#problems-hit-while-building-this">Problems hit</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="python">
  <img src="https://img.shields.io/badge/runtime%20deps-none-success" alt="deps">
  <img src="https://img.shields.io/badge/backend-docker%20%2B%20subprocess-informational" alt="backend">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="license"></a>
</p>

---

## The through-line

```mermaid
flowchart TD
    A["AI-generated code"] --> B["subprocess<br/>(unsafe baseline)"]
    A --> C["docker-baseline<br/>Docker defaults + safety limits"]
    A --> D["hardened<br/>net off · ro rootfs · non-root · cap-drop<br/>no-new-privs · tmpfs workspace · limits"]
    B --> E["30 attacks<br/>harness-scored"]
    C --> E
    D --> E
    E --> F["which attack succeeds<br/>under which profile,<br/>with the mechanism"]

    style D fill:#2563eb,color:#fff
    style F fill:#16a34a,color:#fff
```

The suite runs 30 real attack programs — network egress, secret exfiltration, host-path reads,
fork/memory/disk bombs, `/proc` and `/sys` leaks, privilege and capability probes, raw sockets,
time bombs past the timeout, orphan processes, container-to-host surfaces, symlink tricks on
file-out — under three profiles, several repetitions each. **The harness, not the attacker,
decides whether each attack succeeded**, from evidence it can see for itself: a connection that
actually arrived at a host listener, a canary token it planted and then found in captured
output, a marker file that kept changing after the run returned.

> [!IMPORTANT]
> **Containment results are from the pre-fix run (commit 4f723dd) and are pending a rerun
> and a scoring review.** They were produced before the runtime fixes listed in
> [STATUS.md](STATUS.md) (kill-after on the timeout, streamed output cap, tmpfs workspace,
> OOM read from Docker's state, beacon bound to loopback). In the containment claim and
> tables below, `default` is the profile now named `docker-baseline`: it was never a plain
> `docker run`, because it carried the host-safety limits described under
> [Profiles](#profiles). The latency section *has* been rerun on the fixed runtime.

> **"Docker by itself is a sandbox" is half true. Plain `docker run` did stop every host-level
> attack — the host's env secret, a host file, an orphan process outliving the run. But
> 16 of 30 attacks still succeeded inside it: the code ran as root, reached the network,
> wrote the root filesystem, opened raw sockets and ran every resource bomb to its full size.
> The `hardened` profile cut that to 2 of 30, and both of those are reads of the shared kernel
> that no container flag can hide.**

| profile | attacks that succeeded (3 reps each, all unanimous) |
|---|---|
| `subprocess` — bare host process | **10 / 14** applicable (16 are Linux-only, n/a on this Windows host) |
| `default` — plain `docker run` | **16 / 30** |
| `hardened` | **2 / 30** — `kernel_version_leak`, `mountinfo_leak` |

From [`results/chaos.json`](results/chaos.json): 30 attacks × 3 profiles × 3 repetitions = 270
runs, `python:3.12-slim`. Every one of the 90 cells gave the same verdict in all three
repetitions, and none errored.

## Findings

> [!IMPORTANT]
> Containment results are from the pre-fix run (commit 4f723dd) and are pending a rerun and
> a scoring review (see the note [above](#the-through-line)).

### The full matrix

`succeeded` means the sandbox did **not** contain the attack. `n/a` means the attack is
Linux-only (`/proc`, `setuid`, `fork`, ...) and the subprocess baseline ran on a Windows host.

| # | attack | subprocess | default | hardened | what closes it |
|---|---|---|---|---|---|
| 1 | `tcp_egress` — nonce to a host listener | **succeeded** | **succeeded** | blocked | `--network none` |
| 2 | `udp_egress` | **succeeded** | **succeeded** | blocked | `--network none` |
| 3 | `http_egress` | **succeeded** | **succeeded** | blocked | `--network none` |
| 4 | `dns_resolve` | **succeeded** | **succeeded** | blocked | `--network none` |
| 5 | `env_secret_read` — host env secret | **succeeded** | blocked | blocked | any container (fresh env) |
| 6 | `host_canary_read` — host file by path | **succeeded** | blocked | blocked | any container (mount ns) |
| 7 | `etc_shadow_read` | n/a | **succeeded** | blocked | non-root user |
| 8 | `disk_fill` (bounded, 40 MB) | **succeeded** | **succeeded** | blocked | read-only rootfs |
| 9 | `symlink_fileout` | blocked | blocked | blocked | see [below](#file-out-is-its-own-escape) |
| 10 | `rootfs_write` — write `/etc` | n/a | **succeeded** | blocked | read-only rootfs |
| 11 | `run_as_root` | n/a | **succeeded** | blocked | `--user 65534` |
| 12 | `setuid_escalate` — `setuid(0)` | n/a | **succeeded** | blocked | non-root + cap-drop |
| 13 | `cap_effective` | n/a | **succeeded** (`0xa80425fb`) | blocked (`0x0`) | `--cap-drop ALL` |
| 14 | `raw_socket` | n/a | **succeeded** | blocked | drops `CAP_NET_RAW` |
| 15 | `mount_syscall` | n/a | blocked | blocked | Docker default (no `CAP_SYS_ADMIN`) |
| 16 | `raise_priority` — `nice(-10)` | n/a | blocked | blocked | Docker default (no `CAP_SYS_NICE`) |
| 17 | `kernel_version_leak` — `/proc/version` | n/a | **succeeded** | **succeeded** | nothing: shared kernel |
| 18 | `mountinfo_leak` — `/proc/self/mountinfo` | n/a | **succeeded** | **succeeded** | nothing at this layer |
| 19 | `sysrq_trigger` | n/a | blocked | blocked | Docker default (`/proc` ro) |
| 20 | `kcore_read` | n/a | blocked | blocked | Docker default (masked path) |
| 21 | `dev_mem` | n/a | blocked | blocked | Docker default (minimal `/dev`) |
| 22 | `docker_socket` | n/a | blocked | blocked | not mounted |
| 23 | `cgroupfs_write` | n/a | blocked | blocked | Docker default (`/sys` ro) |
| 24 | `memory_bomb` (bounded, 300 MB) | **succeeded** | **succeeded** | blocked (OOM) | `--memory 128m` |
| 25 | `thread_bomb` (bounded, 200) | **succeeded** | **succeeded** | blocked (at 62) | `--pids-limit 64` |
| 26 | `fork_bomb` (bounded, 300) | n/a | **succeeded** | blocked (at 62) | `--pids-limit 64` |
| 27 | `cpu_spin` | blocked | blocked | blocked | wall-clock timeout |
| 28 | `time_bomb` — fires after timeout | blocked | blocked | blocked | wall-clock timeout |
| 29 | `orphan_survivor` | **succeeded** | blocked | blocked | any container (PID ns) |
| 30 | `output_flood` (~50 MB) | blocked | blocked | blocked | runner's 1 MB output cap |

### What plain Docker gives you, and what it doesn't

- **It does protect the host.** Every attack that needs to reach the host from inside failed
  under `default`. The harness's env secret wasn't visible because the container gets a fresh
  environment. A host file couldn't be read by its path because the mount namespace hides it.
  A detached child couldn't outlive the run: when PID 1 exits, the kernel kills everything in
  the container's PID namespace. The unsafe subprocess baseline failed all three.
- **It does not protect what runs inside it.** Under `default` the code ran as uid 0, kept
  capabilities `0xa80425fb` (including `CAP_NET_RAW` and `CAP_SETUID`), wrote to `/etc`, read
  `/etc/shadow`, reached the harness's host listener over TCP, UDP and HTTP, resolved public
  DNS, and ran the memory, thread and fork bombs to their full bounded size. For code that is
  meant to be contained, "it can't touch my host" is not the whole requirement: that same
  container can still scan your network, exfiltrate whatever it was given, or hold a CPU.
- **Docker's defaults do more than nothing.** `mount`, `nice(-10)`, `/proc/sysrq-trigger`,
  `/proc/kcore`, `/dev/mem` and the cgroup filesystem were already blocked under `default`.
  Docker drops `CAP_SYS_ADMIN` and `CAP_SYS_NICE`, masks `/proc/kcore`, and mounts `/proc/sys`
  and `/sys` read-only. Those rows are blocked in both Docker columns, so they don't separate
  the profiles.
- **`hardened` does not hide the kernel.** `/proc/version` still reports
  `…microsoft-standard-WSL2`, and `/proc/self/mountinfo` still shows the overlay layout. Every
  container shares the host kernel, so a kernel exploit is outside what any of these flags can
  stop. The next step up is gVisor or a microVM (Firecracker).

### File-out is its own escape

`symlink_fileout` plants `out.txt → ../<harness scratch>/canary-…` and waits for the harness to
read `out.txt` back. It is blocked in every column, and
[`results/symlink_ablation.json`](results/symlink_ablation.json) shows why. There are two
separate reasons, and only one of them is the guard:

- **On this Windows host**, the payload did create the link under both Docker profiles
  (`link_created: true`). But Windows sees a Linux symlink on a bind mount as an unreadable
  reparse point, so even a *naive* reader got nothing. The Windows run therefore proves
  nothing about the guard. Under the subprocess backend the payload couldn't create a link at
  all (`WinError 1314`, which needs a privilege it doesn't have).
- **On Linux**, where bind-mount symlinks are real, the same read was repeated inside a
  container. The naive reader returned the canary (`LINUXCANARY-7f3a`), and `read_files_out`
  returned `{}`. That guard refuses symlinks and any path whose resolved target leaves the
  workdir. It is also asserted by a Docker-marked test
  (`test_fileout_guard_on_linux_bind_mount`).

The point: file-out is a channel no container flag closes, because the read happens on the
host side of the mount. The guard has to live in the harness.

### Latency: hardening adds no measurable start-up cost

| profile | first run | median | min | max | n |
|---|---:|---:|---:|---:|---:|
| `subprocess` | 0.547 s | 0.539 s | 0.313 s | 0.969 s | 10 |
| `default` | 5.969 s | 7.766 s | 4.390 s | 22.141 s | 10 |
| `hardened` | 6.219 s | 6.312 s | 3.547 s | 28.421 s | 10 |

Paired per round, hardened minus default had a median of **−0.99 s, 95% CI [−4.80, +1.86]**;
hardened was the slower of the two in 4 of 10 rounds. An ablation that switched off only the
network ([`results/latency_ablation.json`](results/latency_ablation.json), 15 rounds) found:

- network setup costs a median of +0.02 s, CI [−2.16, +3.63];
- the remaining hardening flags cost +0.30 s, CI [−1.91, +0.97].

Every interval contains zero. **At this host's noise level the hardening flags cost nothing
measurable; the price of a sandbox is the container itself — a hardened run's median was
6.3 s against 0.54 s for a bare process, about 12×.** The absolute numbers are slow and heavy-tailed (max 28 s) because this machine was
running other people's training jobs throughout. Profiles were interleaved round-robin so
that load hit every profile equally, and the paired difference is the number to trust, not
the raw medians.

## Profiles

| profile | backend | isolation | limits enforced (from `agent-sandbox profiles` on this Windows host) |
|---|---|---|---|
| `subprocess` | host child process | **none**: sees your files, env and network | wall 10 s, output 1 MB per stream. Memory/fsize/nofile rlimits apply on POSIX only; pids and cpus never |
| `docker-baseline` | Docker | Docker's defaults: bridge network, root, writable rootfs, default caps + seccomp | wall 10 s, output 1 MB, memory 512 MB with swap disabled, cpus 2, pids 512, nofile 1024, fsize 64 MB. `/work` is an **uncapped** host bind mount |
| `hardened` | Docker | `--network none`, `--read-only`, uid 65534, `--cap-drop ALL`, `no-new-privileges`, 16 MB tmpfs `/tmp` | wall 10 s, output 1 MB, memory 128 MB with swap disabled, cpus 1, pids 64, nofile 256, fsize 8 MB, **32 MB tmpfs workspace** |

`docker-baseline` used to be called `default` and was described as "plain `docker run`,
nothing added". That was wrong: it always carried the limits above. The old name still works
as an alias in the Python API.

**How a Docker run works.** `docker run --detach` starts a labelled, uniquely named container
with every flag and limit, idling on `sleep`. `docker exec` then runs the program under
`timeout -k 2 <wall>`: SIGTERM at the budget, SIGKILL 2 s later if the program ignores it.
The harness reads Docker's `OOMKilled` state, copies output files out, and runs
`docker rm --force` in a `finally`, so an exception or Ctrl-C at any point still removes the
container. Before the first run the image is pulled if missing, and the harness checks that
it has a `timeout` supporting `-k`. If it doesn't, the run fails with a clear error instead
of running without a budget.

- **Output** is read in 64 KB chunks while the program runs, up to 1 MB per stream. Past the
  cap the rest is discarded, the program is killed, and `output_truncated` is set, so memory
  in the harness stays bounded whatever the program prints.
- **Out of memory** comes from Docker's `OOMKilled` state, never from program output. A
  program printing `MemoryError` is not reported as OOM. The subprocess backend can't observe
  OOM, so it reports `null` (unknown).
- **Timed out** means the budget fired *and* the program ran for the whole budget. A program
  that calls `sys.exit(124)` early is not reported as timed out.
- **Workspace.** Under `hardened`, `/work` is a 32 MB tmpfs. Inputs are copied in from a
  read-only bind at `/in`, and outputs are copied out with `tar` through `docker exec`,
  keeping only regular files with the requested names. A program can't fill the host disk,
  and can't hand back a symlink. The tmpfs counts against the 128 MB memory limit.

## Input / Output

All five samples are real output, saved in [`results/demo_output.txt`](results/demo_output.txt)
and [`results/cli_samples.txt`](results/cli_samples.txt).

**1. Ordinary code, known answer.** From `uv run python demo.py`: the integers `1 2 3 4 5`
on stdin, summed under `hardened`.

```
profile   : hardened
stdout    : '15'
exit_code : 0
```

**2. Five attacks × three profiles** (same demo, one repetition each):

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

*Each profile fails differently. The subprocess baseline leaks the host secret and leaves an
orphan running. Plain Docker stops both of those but lets the code do anything inside its own
walls. `hardened` stops all five.*

**3. A runaway loop with a 3-second budget:**

```
$ agent-sandbox run --profile hardened --timeout 3 --code "while True: pass"

[docker/hardened] exit=124 12.91s TIMED_OUT
```

*The code was killed at its 3 s budget (exit 124 comes from `timeout` inside the container).
The 12.91 s is wall time including Docker start-up on a busy host. That's why the timeout is
enforced inside the container: enforcing it from outside would have spent most of the budget
before the code even started.*

**4. Network egress under `hardened`:**

```
$ agent-sandbox run --profile hardened --code "import urllib.request; urllib.request.urlopen(\"http://example.com\", timeout=3)"
urllib.error.URLError: <urlopen error [Errno -3] Temporary failure in name resolution>

[docker/hardened] exit=1 6.81s
```

**5. Files in, files out, JSON result:**

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

*`scores.csv` held `alice,3 / bob,5 / carol,4`; the code wrote `report.txt` inside a
read-only-rootfs, no-network container, and the harness read it back.*

## Quick start

```bash
git clone <this repo>
cd agent-sandbox
uv sync                     # installs the package plus pytest/ruff (dev group)

# run code under the hardened profile (needs Docker running)
uv run agent-sandbox run --profile hardened --code "print(2 + 2)"

# see the profiles and the limits actually enforced on this OS
uv run agent-sandbox profiles

# reproduce the latency finding (writes a new file; the committed results are never
# overwritten unless you name them with --out or pass --force)
uv run agent-sandbox latency --rounds 100 --out my_latency.json
```

Commands that need Docker (`chaos`, `latency`, `cleanup`, and `run` with a Docker profile)
fail with a non-zero exit and an `agent-sandbox: error:` line when no engine is running.
`--profile subprocess` prints a warning that the code runs directly on your host.

The Python API mirrors the CLI:

```python
from agent_sandbox import Sandbox

sb = Sandbox()
r = sb.run(
    code="import sys; print(sum(int(x) for x in sys.stdin.read().split()))",
    profile="hardened",
    stdin="1 2 3 4 5",
)
print(r.stdout, r.exit_code, r.duration_s)
```

## Layout

```
src/agent_sandbox/
  types.py               RunSpec / RunResult / Limits — what to run, what was observed
  profiles.py            the three named profiles (subprocess / docker-baseline / hardened)
  runner.py              Sandbox: pick a backend, apply limits; which limits this OS enforces
  latency.py             counterbalanced, paired latency: Hodges-Lehmann + Wilcoxon CI, MDE
  cli.py                 run / profiles / chaos / latency / cleanup
  backends/
    docker_cmd.py        pure `docker run --detach` / `docker exec` argv builders (no engine)
    docker.py            pre-flight, labelled containers, OOMKilled, tar copy-out, rm in finally
    subprocess_backend.py the unsafe baseline (host child process)
    base.py              streamed, byte-capped output capture + symlink-safe file-out reader
  attacks/
    harness.py           HostBeacon (TCP+UDP), ChaosContext, AttackOutcome
    registry.py          30 attacks: payload + harness-side objective check
  chaos.py               run every attack x every profile x N reps, score, report
demo.py                  known-answer demo (output saved in results/demo_output.txt)
scripts/
  run_chaos.sh           full suite + latency + cleanup
  latency_ablation.py    docker-baseline vs baseline-without-network vs hardened
  symlink_ablation.py    guarded vs naive file-out reader, Windows host + Linux simulation
results/                 chaos, latency, both ablations, demo and CLI output —
                         every README number comes from a file here
```

## Requirements

Python 3.11+, `uv`, and a running Docker engine for the `docker-baseline`/`hardened` profiles
(the `subprocess` baseline and the whole unit-test suite run without one). Only
`python:3.12-slim` is pulled, from Docker Hub; any image works if it has `python`, `sleep`,
`tar`, `cp`, `sh` and a coreutils-style `timeout` with `-k` (`timeout -k` and `sleep` are
checked before the first run). **Zero runtime dependencies** — the package is pure standard library;
`pytest`/`ruff` are dev-only.

## Tests

```bash
uv run pytest -q                   # 179 tests (~3 min with Docker)
uv run pytest -q -m "not docker"   # unit-only: fakes, no engine, no network
uv run pytest -q -m docker         # integration: real containers (auto-skipped if no engine)
```

157 unit tests cover the argv builder, the profiles and limit validation (a zero timeout is
rejected, because `timeout 0` would mean *no* timeout), workdir-escaping file paths, every
harness-side check with fabricated `RunResult`s, the subprocess backend, the file-out guard, the
latency design (interleaving; a fake with drifting load checks that pairing recovers the true
difference) and the CLI's error messages. The 22 Docker-marked tests run real containers,
including the Linux file-out guard check, and are skipped automatically when no engine is
present.
Tests are hermetic: no network (the beacon test is loopback-only), no model, no reliance on data
that grows.

## What this does NOT do

- **It is not a production sandbox.** It is a measurement harness plus a reference hardened
  profile. Use gVisor, Firecracker, or a managed sandbox for untrusted code in production.
- **It does not defeat a kernel exploit.** Every profile shares the host kernel (that is why the
  `kernel_version_leak` attack succeeds under Docker too). A kernel-level escape is out of scope.
- **It does not test seccomp bypasses exhaustively.** It uses Docker's default seccomp profile
  and measures capability/syscall attacks against it; it is not a seccomp fuzzer.
- **The subprocess baseline is intentionally unsafe.** It exists to be beaten, not shipped.
- **`docker-baseline` is not a naked `docker run`.** So that a resource bomb can't take down
  the test machine, it carries a loose host-safety floor (512 MB memory with swap disabled,
  512 pids, 2 cpus, 1024 files, 64 MB file size) plus a wall-clock timeout. The chaos suite's
  bombs are bounded below that floor. Its `/work` is an uncapped host bind mount; only
  `hardened` caps the workspace. On Windows the subprocess baseline enforces only the wall
  clock and the output cap: no memory, pids, cpu or disk limits at all.
- **The subprocess column covers 14 of 30 attacks.** The baseline ran on a Windows host, where
  the 16 `/proc`- and syscall-based attacks don't apply. They are reported as `n/a`, never as
  blocked.

## Problems hit while building this

- **The hardened profile hid the code it was supposed to run.** The first version mounted `/work`
  as a size-capped tmpfs *and* wrote `main.py` to a host dir that was never bound — so the
  container started with an empty `/work` and `python: can't open '/work/main.py'`. The quick
  fix made `/work` a host bind mount, which then left the workspace with no size limit at all:
  a program could fill the host disk. `/work` is now a tmpfs again, with inputs copied in from
  a read-only `/in` bind and outputs copied out with `tar` after the program exits. That needs
  the container to outlive the program, which is why a run is `docker run --detach` plus
  `docker exec`.
- **A program that ignored SIGTERM ran 44.9 s against a 3 s budget.** The in-container
  `timeout` only sent SIGTERM, so a program with `signal(SIGTERM, SIG_IGN)` was stopped only
  by the outer 40 s safety net. It is now `timeout -k 2`: SIGKILL 2 s after the budget. The
  regression test (a SIGTERM-ignoring sleeper, 3 s budget) now ends at exit 137 within about
  5.5 s of program time.
- **The 1 MB output cap didn't bound memory.** Both backends read all output with
  `communicate()` and truncated it afterwards, so a program printing without end made the
  harness buffer all of it. Output is now streamed in chunks with a byte cap, and the program is
  killed once it passes the cap.
- **"Out of memory" was whatever the program said.** A run was flagged OOM if stderr contained
  `MemoryError`, which any program can print. It now comes from Docker's `OOMKilled` state. The
  same logic had treated a self-chosen `sys.exit(124)` as a timeout; a timeout now also needs
  the program to have run for the whole budget.
- **A container killed from outside looked like a program result.** The first 100-round
  ablation stopped with `stdout = 'cannot exec in a stopped state'`: the container got a
  SIGKILL right after `docker exec` started, and Docker's event log had already dropped
  enough history that the sender couldn't be identified. The program cannot have done it,
  because PID 1 is `sleep` and ignores signals sent from inside the container. The harness had
  passed Docker's error text through as the program's output. It now reads
  `State.Running`, and a container that stopped with no OOM and no harness kill is reported as
  an `error`. The ablation was then rerun from scratch.
- **Ctrl-C leaked containers.** Only `TimeoutExpired` triggered a kill, so a
  `KeyboardInterrupt` mid-run left the container running. Any exception now kills it, and
  `docker rm --force` runs in a `finally`.
- **The first orphan check said the subprocess baseline was safe. It wasn't.** The check
  waited 1.5 s for a detached child's marker file to change. On this loaded machine the child
  took longer than that just to start, so all three repetitions came back `blocked`.
  Reproducing it by hand showed the marker appearing only after the check had given up. The check now polls for up to
  10 s and needs two distinct marker values (proof of a *live* process), and the verdict
  flipped to `succeeded`. The Docker side had the opposite problem: the child wrote to a host
  path that doesn't exist inside the container, so it died of a write error, not of the
  sandbox. It now writes to a real in-container path, and the harness checks from the host
  that the container itself is gone.
- **Docker start-up was eating the timeout.** On this machine a cold `docker run` often took
  longer than the whole 10 s budget before the code even started (sample 3 above shows 12.91 s
  of wall time for a 3 s budget). Enforcing the budget from
  outside marked ordinary runs as timed out. The budget is now enforced inside the container
  with coreutils `timeout`, and container start-up has its own separate 90 s limit. Resource
  bombs get a 30 s budget, so they are stopped by the limit they target and never by the clock.
- **Two `hardened` "breaches" were the harness's mistakes.** `kcore_read` counted a
  successful `open()` as a leak, but Docker masks `/proc/kcore`, so the read returned 0 bytes.
  It now needs real bytes. `pid1_environ` read `/proc/1/environ`, but in a one-process
  container PID 1 *is* the payload, so it was reading its own environment; it was removed.
  Without these fixes the `hardened` count would have been double the true one.
- **The symlink attack first missed its own target.** It linked to the canary by absolute
  Windows path, which means nothing inside a Linux container. It now uses a relative `../`
  path that resolves on the host side of the bind mount. Even then, Windows can't read a Linux
  symlink on a bind mount (a reparse point, `EINVAL`), so the guard's real test runs on Linux
  (see [File-out is its own escape](#file-out-is-its-own-escape)).
- **A missing count was being scored as a defence.** `thread_bomb` under subprocess once came
  back "stopped at None": the 10 s clock killed it before it printed, under load. "No count
  reached the harness" is now reported as `error`, never as `blocked`.
- **Docker availability was probed per cell and flapped.** On a busy host `docker info` timed
  out intermittently, and Docker cells silently disappeared from one run's matrix. The
  engine is now probed once, with the lighter `docker version`, and a positive answer is
  cached.
- **Latency measured in sequence measured the neighbours.** An early block-by-block run made
  `hardened` look several seconds faster than `default`. That was host load drifting between
  the two blocks, not the flags. Profiles were then interleaved, but always in the same order,
  so a position effect would still have been counted as a profile effect. The order is now
  shuffled every round, and the analysis is paired and robust, with the minimum detectable
  effect reported.
- **The egress beacon listened on every interface.** It was documented as loopback but bound
  to `0.0.0.0`, so anything on the LAN could reach it while the suite ran. It now binds
  `127.0.0.1`. Before the change, a probe container confirmed that Docker Desktop still
  delivers both TCP and UDP from `host.docker.internal` to a listener on the host's loopback.
- **Killing safely on a shared box.** Timeouts must tear down runaway work without touching other
  people's processes. Containers are killed by their unique name; subprocess trees by the exact
  PID launched (`taskkill /T` / `killpg`); a would-be orphan is killed only by the child PID the
  attack itself prints. No pattern-matching kills anywhere.

## Keywords

sandbox &middot; code execution &middot; Docker &middot; container security &middot; seccomp &middot; cgroups &middot; capabilities &middot; AI-generated code &middot; untrusted code &middot; escape testing &middot; network egress &middot; privilege escalation &middot; resource limits &middot; hardening &middot; defence in depth

## License

MIT. Inspired by [daytonaio/daytona](https://github.com/daytonaio/daytona); no code from it is used.
