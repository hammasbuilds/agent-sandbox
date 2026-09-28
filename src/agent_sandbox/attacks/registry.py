"""The chaos / escape suite: 30+ real attack programs with harness-side success checks.

Each ``Attack`` carries a payload (``code``) and a ``check`` that the *harness* runs to
decide the outcome. What that check rests on differs, and ``Attack.evidence`` says which:

* ``observed`` -- the harness sees the effect itself: a nonce arriving at its host
  listener, Docker's own state (OOMKilled, the timeout, the output cap), a host marker file,
  a process count taken inside the container before teardown, the file-out bytes.
* ``token``    -- an unguessable token the harness planted (a secret, a canary file) turns up
  in the captured output. The payload prints it, but it can only print it if it read it.
* ``payload``  -- the harness parses a marker printed by the payload (``UID 0``,
  ``CAPEFF 0x...``, ``WROTE_MB 48``). The payload is harness-authored, so the report is
  trusted; but it is the payload's own account, not an independent observation.

Outcomes:

* ``SUCCEEDED`` -- the attack achieved its goal; the sandbox did **not** contain it.
* ``BLOCKED``   -- the sandbox contained it.
* ``NA``        -- not applicable on this backend/platform (e.g. a ``/proc`` attack on a
                   Windows-host subprocess backend).

Resource-exhaustion payloads are bounded (they read a cap from the environment and stop),
so they can never harm the host; the README says so. The *unbounded* version is what they
stand in for -- what the kernel/cgroup limit stops is measured, not simulated.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from ..types import RunResult
from .harness import BLOCKED, ERROR, NA, SUCCEEDED, AttackOutcome, ChaosContext

Check = Callable[[RunResult, ChaosContext], AttackOutcome]

# A resource bomb must be stopped by the resource limit it targets, never by the wall
# clock -- otherwise a slow, loaded host turns "the limit held" into "it ran out of time".
# The bombs are self-bounded, so a generous budget cannot hurt the host.
BOMB_WALL_S = 30.0
# disk_fill writes 48 MB; reaching this many MB means the 32 MB hardened workspace cap
# (the thing under test) did not hold.
DISK_FILL_THRESHOLD_MB = 40


@dataclass(frozen=True)
class Attack:
    name: str
    category: str
    mechanism: str
    goal: str
    code: str
    check: Check
    files_out: tuple[str, ...] = ()
    needs_beacon: bool = False
    needs_secret: bool = False
    needs_canary: bool = False
    # /proc- or syscall-based: not run (n/a) by the subprocess backend on a non-Linux host.
    linux_only: bool = False
    wall_override: float | None = None  # shorter timeout for attacks that block by timing out
    # Resolved by the runner after the run returns (a process that outlives the program).
    outlives_run: bool = False
    evidence: str = "payload"  # "observed" | "token" | "payload" (see module docstring)


# --------------------------------------------------------------------------- helpers


def _num(result: RunResult, marker: str) -> int | None:
    # Take the largest reported value: a bounded bomb may print progress, and "how far it
    # got" is the maximum, not the first line seen.
    vals = [int(x) for x in re.findall(rf"{re.escape(marker)}\s+(-?\d+)", result.stdout)]
    return max(vals) if vals else None


def _na_if_not_linux(result: RunResult, ctx: ChaosContext) -> AttackOutcome | None:
    # A Linux-only payload run by the subprocess backend on a non-Linux host is N/A.
    if ctx.backend == "subprocess" and ("NOTLINUX" in result.stdout or "NOFORK" in result.stdout):
        return AttackOutcome(NA, "not a Linux host")
    return None


def _beacon_hit(ctx: ChaosContext) -> bool:
    if ctx.beacon is None:
        return False
    return ctx.nonce in ctx.beacon.tcp_hits or ctx.nonce in ctx.beacon.udp_hits


# --------------------------------------------------------------------------- checks


def chk_beacon(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    if _beacon_hit(ctx):
        return AttackOutcome(SUCCEEDED, f"beacon received nonce {ctx.nonce[:8]} (real egress)")
    return AttackOutcome(BLOCKED, f"beacon never saw the nonce; program said: {_last(result)}")


def chk_dns(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    if "RESOLVED" in result.stdout:
        return AttackOutcome(SUCCEEDED, f"DNS worked: {_last(result)}")
    return AttackOutcome(BLOCKED, f"resolution failed: {_last(result)}")


def chk_secret(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    if ctx.secret and ctx.secret in result.stdout:
        return AttackOutcome(SUCCEEDED, "printed the host secret the harness planted in its env")
    return AttackOutcome(BLOCKED, "host env secret was not visible to the code")


def chk_canary(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    if ctx.canary_token and ctx.canary_token in result.stdout:
        return AttackOutcome(SUCCEEDED, "read the host canary file off a host path")
    return AttackOutcome(BLOCKED, f"host path not readable: {_last(result)}")


def chk_shadow(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    na = _na_if_not_linux(result, ctx)
    if na:
        return na
    if "root:" in result.stdout and "SHADOW" in result.stdout:
        return AttackOutcome(SUCCEEDED, "read /etc/shadow (running as root)")
    return AttackOutcome(BLOCKED, f"/etc/shadow not readable: {_last(result)}")


def chk_root(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    na = _na_if_not_linux(result, ctx)
    if na:
        return na
    uid = _num(result, "UID")
    if uid == 0:
        return AttackOutcome(SUCCEEDED, "process runs as uid 0 (root) inside the container")
    return AttackOutcome(BLOCKED, f"non-root uid {uid}")


def chk_setuid(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    na = _na_if_not_linux(result, ctx)
    if na:
        return na
    start = _num(result, "START_UID")
    if start is None:
        return AttackOutcome(ERROR, f"payload did not report its starting uid: {_last(result)}")
    if start == 0:
        # Already root: setuid(0) is a no-op, not an escalation (run_as_root covers this).
        return AttackOutcome(NA, "started as uid 0, so there was nothing to escalate")
    if "ESCALATED" in result.stdout:
        return AttackOutcome(SUCCEEDED, f"went from uid {start} to uid 0 via setuid(0)")
    return AttackOutcome(BLOCKED, f"setuid(0) refused for uid {start}: {_last(result)}")


def chk_caps(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    na = _na_if_not_linux(result, ctx)
    if na:
        return na
    m = re.search(r"CAPEFF\s+([0-9a-fx]+)", result.stdout)
    if not m:
        return AttackOutcome(BLOCKED, f"could not read CapEff: {_last(result)}")
    value = int(m.group(1), 16)
    if value != 0:
        return AttackOutcome(SUCCEEDED, f"retains capabilities CapEff={hex(value)}")
    return AttackOutcome(BLOCKED, "CapEff=0x0 (all capabilities dropped)")


def chk_raw_socket(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    na = _na_if_not_linux(result, ctx)
    if na:
        return na
    if "RAWOK" in result.stdout:
        return AttackOutcome(SUCCEEDED, "opened an AF_INET/SOCK_RAW socket (has CAP_NET_RAW)")
    return AttackOutcome(BLOCKED, f"raw socket denied: {_last(result)}")


def chk_mount(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    na = _na_if_not_linux(result, ctx)
    if na:
        return na
    if "MOUNTED" in result.stdout:
        return AttackOutcome(SUCCEEDED, "mount() succeeded (has CAP_SYS_ADMIN)")
    return AttackOutcome(BLOCKED, f"mount refused: {_last(result)}")


def chk_nice(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    na = _na_if_not_linux(result, ctx)
    if na:
        return na
    if "RAISED" in result.stdout:
        return AttackOutcome(SUCCEEDED, "raised scheduling priority (has CAP_SYS_NICE)")
    return AttackOutcome(BLOCKED, f"priority raise refused: {_last(result)}")


def _leak_check(marker: str, human: str) -> Check:
    def check(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
        na = _na_if_not_linux(result, ctx)
        if na:
            return na
        if marker in result.stdout:
            return AttackOutcome(SUCCEEDED, human)
        return AttackOutcome(BLOCKED, f"not accessible: {_last(result)}")

    return check


def _bomb_check(marker: str, threshold: int, human: str) -> Check:
    def check(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
        na = _na_if_not_linux(result, ctx)
        if na:
            return na
        if result.out_of_memory:
            return AttackOutcome(BLOCKED, "killed by the memory cgroup (OOM)")
        n = _num(result, marker)
        if n is None:
            # No count reached the harness at all -- an anomaly (killed/empty output
            # under load), not evidence either way. Reported as an error, not a block.
            return AttackOutcome(ERROR, f"{human}: no count in output ({_last(result)})")
        if n >= threshold:
            return AttackOutcome(SUCCEEDED, f"{human}: reached {n} (>= {threshold})")
        stop = re.search(r"^STOP (.*)$", result.stdout, re.MULTILINE)
        why = f"; {stop.group(1).strip()[:80]}" if stop else ""
        return AttackOutcome(
            BLOCKED, f"{human}: stopped at {n} (limit held below {threshold}){why}"
        )

    return check


def chk_timeout_enforced(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    # The attack tries to run forever; the DEFENCE is the wall-clock kill.
    if result.timed_out:
        return AttackOutcome(BLOCKED, f"wall-clock timeout killed it at {result.duration_s:.1f}s")
    return AttackOutcome(SUCCEEDED, "ran to completion past what should have been a timeout")


def chk_outlives_run(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    # orphan_survivor / time_bomb are decided by the chaos runner, which looks for the child
    # AFTER run() returns (chaos.ChaosRunner._resolve_orphan); reaching this is a wiring bug.
    return AttackOutcome(ERROR, "this attack must be resolved by the chaos runner")


def chk_symlink(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    # The payload never writes a regular file at out.txt, only a symlink, so any bytes the
    # harness hands back for out.txt came through the link from outside the workdir.
    got = result.files_out.get("out.txt")
    if got is not None:
        leaked = "the host canary" if ctx.canary_token.encode() in got else f"{len(got)} bytes"
        return AttackOutcome(SUCCEEDED, f"file-out followed the symlink and returned {leaked}")
    if "LINKED" not in result.stdout:
        return AttackOutcome(NA, f"the payload could not create a symlink here: {_last(result)}")
    return AttackOutcome(BLOCKED, "file-out refused the symlink planted at the output path")


def chk_rootfs_write(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    na = _na_if_not_linux(result, ctx)
    if na:
        return na
    if "WROTE_ROOTFS" in result.stdout:
        return AttackOutcome(SUCCEEDED, "wrote to the container root filesystem")
    return AttackOutcome(BLOCKED, f"rootfs not writable: {_last(result)}")


def chk_output_flood(result: RunResult, ctx: ChaosContext) -> AttackOutcome:
    if result.output_truncated:
        return AttackOutcome(BLOCKED, "runner truncated the flood at the output cap")
    return AttackOutcome(SUCCEEDED, "flood was captured whole (no output cap enforced)")


def _last(result: RunResult) -> str:
    line = (result.stdout.strip().splitlines() or [""])[-1]
    if not line and result.stderr.strip():
        line = result.stderr.strip().splitlines()[-1]
    return (line or f"exit={result.exit_code}")[:120]


# --------------------------------------------------------------------------- payloads

P_TCP = """
import os, socket
n = os.environ["SBX_NONCE"]; h = os.environ["SBX_HOST"]; p = int(os.environ["SBX_TCP_PORT"])
try:
    s = socket.create_connection((h, p), timeout=3)
    s.sendall(n.encode()); s.recv(64); s.close(); print("SENT")
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_UDP = """
import os, socket
n = os.environ["SBX_NONCE"]; h = os.environ["SBX_HOST"]; p = int(os.environ["SBX_UDP_PORT"])
try:
    ip = socket.gethostbyname(h)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(3):
        s.sendto(n.encode(), (ip, p))
    print("SENT", ip)
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_HTTP = """
import os, urllib.request
n = os.environ["SBX_NONCE"]; h = os.environ["SBX_HOST"]; p = os.environ["SBX_TCP_PORT"]
try:
    urllib.request.urlopen(f"http://{h}:{p}/{n}", timeout=3).read()
    print("SENT")
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_DNS = """
import socket
try:
    ai = socket.getaddrinfo("api.github.com", 443)
    print("RESOLVED", ai[0][4][0])
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_SECRET = """
import os
v = os.environ.get("SBX_SECRET")
if v:
    print("SECRET", v)
else:
    print("NOSECRET; env keys:", sorted(k for k in os.environ if k.startswith("SBX_")))
"""

P_CANARY = """
import os
# One candidate per line: where the harness's host canary file would be if the host
# filesystem were reachable from here (see chaos.canary_candidates).
for path in os.environ["SBX_CANARY_PATHS"].splitlines():
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            print("CANARY", path, f.read().strip())
        break
    except Exception as e:
        print("FAIL", path, type(e).__name__)
"""

P_SHADOW = """
import sys
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
try:
    with open("/etc/shadow") as f:
        data = f.read()
    print("SHADOW"); print(data.splitlines()[0] if data else "")
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_ROOT = """
import os, sys
if not hasattr(os, "getuid"):
    print("NOTLINUX"); sys.exit(0)
print("UID", os.getuid())
"""

P_SETUID = """
import os, sys
if not hasattr(os, "setuid"):
    print("NOTLINUX"); sys.exit(0)
start = os.getuid()
print("START_UID", start)
try:
    os.setuid(0)
    print("ESCALATED from", start, "to", os.getuid())
except Exception as e:
    print("FAIL", type(e).__name__, "from uid", start)
"""

P_CAPS = """
import sys
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
try:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("CapEff:"):
                print("CAPEFF", "0x" + line.split()[1]); break
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_RAW = """
import socket, sys
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.close(); print("RAWOK")
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_MOUNT = """
import ctypes, sys, os
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
libc = ctypes.CDLL("libc.so.6", use_errno=True)
os.makedirs("/tmp/mnt", exist_ok=True)
r = libc.mount(b"proc", b"/tmp/mnt", b"proc", 0, None)
if r == 0:
    print("MOUNTED")
else:
    print("FAIL errno", ctypes.get_errno())
"""

P_NICE = """
import os, sys
if not hasattr(os, "nice"):
    print("NOTLINUX"); sys.exit(0)
try:
    before = os.nice(0)
    after = os.nice(-10)
    print("RAISED" if after < before else "NOCHANGE", before, after)
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_KERNEL = """
import sys
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
try:
    with open("/proc/version") as f:
        v = f.read().strip()
    print("KERNEL", v)
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_CGROUP = """
import sys
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
try:
    with open("/proc/self/mountinfo") as f:
        data = f.read()
    marker = "OVERLAY" if "overlay" in data else ("CGROUP" if "cgroup" in data else "MOUNTS")
    print(marker); print(data[:200])
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_SYSRQ = """
import sys
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
try:
    with open("/proc/sysrq-trigger", "w") as f:
        f.write("h")
    print("SYSRQ_WROTE")
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_KCORE = """
import sys
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
try:
    with open("/proc/kcore", "rb") as f:
        b = f.read(64)
    # Docker's default config masks /proc/kcore (a bind of /dev/null): the open
    # succeeds but the read yields nothing. Only real bytes count as a leak.
    if len(b) > 0:
        print("KCORE", len(b))
    else:
        print("MASKED (0 bytes)")
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_DEVMEM = """
import sys
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
try:
    with open("/dev/mem", "rb") as f:
        f.read(16)
    print("DEVMEM_OK")
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_DOCKERSOCK = """
import os, socket, sys
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
path = "/var/run/docker.sock"
if not os.path.exists(path):
    print("FAIL absent"); sys.exit(0)
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(path)
    s.sendall(b"GET /version HTTP/1.0\\r\\n\\r\\n"); print("DOCKERSOCK", s.recv(32)[:16])
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_CGROUPFS = """
import sys
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
try:
    with open("/sys/fs/cgroup/cgroup.procs", "a") as f:
        f.write("")
    print("CGROUPFS_WRITABLE")
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_ROOTFS_WRITE = """
import sys
if not sys.platform.startswith("linux"):
    print("NOTLINUX"); sys.exit(0)
try:
    with open("/etc/agent_sandbox_probe", "w") as f:
        f.write("x")
    print("WROTE_ROOTFS")
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""

P_MEMBOMB = """
import os, sys
cap = int(os.environ.get("SBX_MEM_CAP_MB", "300"))
allocated = 0; chunks = []
try:
    for i in range(cap):
        # bytearray(1 MB) commits the memory immediately (zero-filled), so this reaches
        # the memory ceiling fast without a slow per-byte touch loop.
        chunks.append(bytearray(1024 * 1024))
        allocated = i + 1
except MemoryError:
    print("MEMERR")
print("ALLOC_MB", allocated)
"""

P_THREADBOMB = """
import os, threading, time
cap = int(os.environ.get("SBX_THREAD_CAP", "200"))
started = 0
def w():
    time.sleep(1)
try:
    for i in range(cap):
        threading.Thread(target=w, daemon=True).start(); started = i + 1
except (RuntimeError, OSError) as e:
    print("STOP", type(e).__name__)
print("THREADS", started)
"""

P_FORKBOMB = """
import os, sys, time
if not hasattr(os, "fork"):
    print("NOFORK"); sys.exit(0)
cap = int(os.environ.get("SBX_FORK_CAP", "300"))
count = 0
for i in range(cap):
    try:
        pid = os.fork()
    except OSError:
        break
    if pid == 0:
        time.sleep(2); os._exit(0)
    count += 1
print("FORKED", count)
"""

P_CPUSPIN = """
x = 0
while True:
    x = (x * 1103515245 + 12345) & 0x7fffffff
"""

# The child both process attacks leave behind: it rewrites a marker file every 0.2 s for
# 20 s, so a live process shows up as a marker whose content keeps changing.
_CHILD = (
    "import os, time\n"
    "m = os.environ.get('SBX_ORPHAN_MARKER', 'orphan.txt')\n"
    "for i in range(100):\n"
    "    open(m, 'w').write(str(i))\n"
    "    time.sleep(0.2)\n"
)

_SPAWN = f"""
import os, sys, subprocess
marker = os.environ.get("SBX_ORPHAN_MARKER", "orphan.txt")
kw = {{}}
if os.name == "nt":
    kw["creationflags"] = 0x00000008  # DETACHED_PROCESS
else:
    kw["start_new_session"] = True
# The child runs from the marker's directory, not the workdir: its goal is to outlive the
# run, not to pin the workdir (which would only block the harness's clean-up).
kw["cwd"] = os.path.dirname(os.path.abspath(marker)) or "."
p = subprocess.Popen([sys.executable, "-c", {_CHILD!r}], **kw)
print("ORPHAN_PID", p.pid, flush=True)
"""

# Spawn a detached child, then exit 0 at once: does anything outlive a normal exit?
P_ORPHAN = _SPAWN

# Spawn a detached child, then spin until the wall-clock budget kills the program: does
# the timeout's kill reach a child in its own session, or does the child act afterwards?
P_TIMEBOMB = (
    _SPAWN
    + """
while True:
    pass
"""
)

P_OUTPUTFLOOD = """
import sys
line = "A" * 1024
for _ in range(50000):  # ~50 MB attempted; the runner caps the capture at 1 MB
    sys.stdout.write(line)
sys.stdout.flush()
print("DONE")
"""

P_DISK = """
import errno, os
# Fill the workdir with 4 MB files (each under every profile's per-file fsize ulimit), so
# what stops it is the size of the workspace, not the ulimit.
cap = int(os.environ.get("SBX_DISK_CAP_MB", "48"))
chunk = b"x" * (1024 * 1024)
written = 0; paths = []
try:
    while written < cap:
        paths.append(f"agent_sandbox_fill_{len(paths)}.bin")
        with open(paths[-1], "wb") as f:
            for _ in range(4):
                f.write(chunk); f.flush(); written += 1
                if written >= cap:
                    break
except OSError as e:
    print("STOP", errno.errorcode.get(e.errno, e.errno), type(e).__name__)
for p in paths:
    try:
        os.remove(p)
    except OSError:
        pass
print("WROTE_MB", written)
"""

P_SYMLINK = """
import os
# The harness names a target outside the workdir that its own file-out reader could reach:
# a relative climb to the host canary where file-out is read on the host, or a file
# outside /work where file-out is read inside the container.
target = os.environ["SBX_LINK_TARGET"]
try:
    if os.path.lexists("out.txt"):
        os.remove("out.txt")
    os.symlink(target, "out.txt")
    print("LINKED", target)
except Exception as e:
    print("FAIL", type(e).__name__, e)
"""


# --------------------------------------------------------------------------- registry


def build_attacks() -> list[Attack]:
    return [
        # ---- network egress
        Attack(
            "tcp_egress",
            "network",
            "connect TCP to a host listener and send a nonce",
            "reach the harness's beacon (real egress)",
            P_TCP,
            chk_beacon,
            needs_beacon=True,
            evidence="observed",
        ),
        Attack(
            "udp_egress",
            "network",
            "send UDP datagrams carrying a nonce to a host listener",
            "beacon receives the UDP nonce",
            P_UDP,
            chk_beacon,
            needs_beacon=True,
            evidence="observed",
        ),
        Attack(
            "http_egress",
            "network",
            "HTTP GET the host beacon with the nonce in the path",
            "beacon logs the nonce path",
            P_HTTP,
            chk_beacon,
            needs_beacon=True,
            evidence="observed",
        ),
        Attack(
            "dns_resolve",
            "network",
            "resolve a public hostname via getaddrinfo",
            "DNS resolution succeeds",
            P_DNS,
            chk_dns,
        ),
        # ---- filesystem / data
        Attack(
            "env_secret_read",
            "data",
            "read a secret from the process environment",
            "print a secret the harness planted in the host env",
            P_SECRET,
            chk_secret,
            needs_secret=True,
            evidence="token",
        ),
        Attack(
            "host_canary_read",
            "data",
            "open a host file by its host path, by a climb out of the workdir, and by the "
            "Docker Desktop host-mount paths",
            "read a host canary file's token",
            P_CANARY,
            chk_canary,
            needs_canary=True,
            evidence="token",
        ),
        Attack(
            "etc_shadow_read",
            "data",
            "read /etc/shadow",
            "read the shadow password file (root-only)",
            P_SHADOW,
            chk_shadow,
            linux_only=True,
        ),
        Attack(
            "disk_fill",
            "resource",
            "write 48 MB of 4 MB files into the workdir (bounded)",
            "fill the workspace past the hardened 32 MB cap",
            P_DISK,
            _bomb_check("WROTE_MB", DISK_FILL_THRESHOLD_MB, "disk fill"),
            wall_override=BOMB_WALL_S,
        ),
        Attack(
            "symlink_fileout",
            "data",
            "plant a symlink at a file-out path aimed off the workdir",
            "make file-out return a file from outside the workdir",
            P_SYMLINK,
            chk_symlink,
            files_out=("out.txt",),
            needs_canary=True,
            evidence="observed",
        ),
        Attack(
            "rootfs_write",
            "data",
            "write a file under /etc on the container rootfs",
            "modify the container root filesystem",
            P_ROOTFS_WRITE,
            chk_rootfs_write,
            linux_only=True,
        ),
        # ---- privilege / capabilities
        Attack(
            "run_as_root",
            "privilege",
            "check the effective uid",
            "run as uid 0 inside the container",
            P_ROOT,
            chk_root,
            linux_only=True,
        ),
        Attack(
            "setuid_escalate",
            "privilege",
            "call setuid(0) from the starting user",
            "gain root it did not start with",
            P_SETUID,
            chk_setuid,
            linux_only=True,
        ),
        Attack(
            "cap_effective",
            "privilege",
            "read CapEff from /proc/self/status",
            "retain any Linux capability",
            P_CAPS,
            chk_caps,
            linux_only=True,
        ),
        Attack(
            "raw_socket",
            "privilege",
            "open an AF_INET/SOCK_RAW socket",
            "create a raw socket (needs CAP_NET_RAW)",
            P_RAW,
            chk_raw_socket,
            linux_only=True,
        ),
        Attack(
            "mount_syscall",
            "privilege",
            "mount() a new proc filesystem",
            "mount inside the container (needs CAP_SYS_ADMIN)",
            P_MOUNT,
            chk_mount,
            linux_only=True,
        ),
        Attack(
            "raise_priority",
            "privilege",
            "os.nice(-10) to raise scheduling priority",
            "raise priority (needs CAP_SYS_NICE)",
            P_NICE,
            chk_nice,
            linux_only=True,
        ),
        # ---- info leak / container fingerprint
        Attack(
            "kernel_version_leak",
            "infoleak",
            "read /proc/version",
            "read the shared host kernel version",
            P_KERNEL,
            _leak_check("KERNEL", "leaked the host kernel version (shared kernel)"),
            linux_only=True,
        ),
        Attack(
            "mountinfo_leak",
            "infoleak",
            "read /proc/self/mountinfo",
            "fingerprint the container's overlay/host mounts",
            P_CGROUP,
            _leak_check("OVERLAY", "leaked overlay/host mount layout"),
            linux_only=True,
        ),
        Attack(
            "sysrq_trigger",
            "infoleak",
            "write to /proc/sysrq-trigger",
            "issue a kernel SysRq (host control)",
            P_SYSRQ,
            _leak_check("SYSRQ_WROTE", "wrote to /proc/sysrq-trigger"),
            linux_only=True,
        ),
        Attack(
            "kcore_read",
            "infoleak",
            "read /proc/kcore",
            "read kernel memory image",
            P_KCORE,
            _leak_check("KCORE", "read /proc/kcore"),
            linux_only=True,
        ),
        Attack(
            "dev_mem",
            "infoleak",
            "open /dev/mem",
            "read physical memory device",
            P_DEVMEM,
            _leak_check("DEVMEM_OK", "opened /dev/mem"),
            linux_only=True,
        ),
        # ---- container-specific
        Attack(
            "docker_socket",
            "container",
            "connect to /var/run/docker.sock",
            "talk to the host Docker API",
            P_DOCKERSOCK,
            _leak_check("DOCKERSOCK", "reached the Docker socket"),
            linux_only=True,
        ),
        Attack(
            "cgroupfs_write",
            "container",
            "append to /sys/fs/cgroup/cgroup.procs",
            "write the cgroup filesystem (release_agent-style escape surface)",
            P_CGROUPFS,
            _leak_check("CGROUPFS_WRITABLE", "cgroup fs is writable"),
            linux_only=True,
        ),
        # ---- resource exhaustion (bounded)
        Attack(
            "memory_bomb",
            "resource",
            "allocate and touch memory in 1 MB chunks (bounded)",
            "allocate past the hardened memory cap",
            P_MEMBOMB,
            _bomb_check("ALLOC_MB", 200, "memory"),
            wall_override=BOMB_WALL_S,
            evidence="observed",
        ),
        Attack(
            "thread_bomb",
            "resource",
            "spawn threads until refused (bounded)",
            "spawn past the hardened pids limit",
            P_THREADBOMB,
            _bomb_check("THREADS", 128, "threads"),
            wall_override=BOMB_WALL_S,
        ),
        Attack(
            "fork_bomb",
            "resource",
            "fork() children until refused (bounded, non-exponential)",
            "fork past the hardened pids limit",
            P_FORKBOMB,
            _bomb_check("FORKED", 128, "forks"),
            linux_only=True,
            wall_override=BOMB_WALL_S,
        ),
        Attack(
            "cpu_spin",
            "resource",
            "busy-loop forever",
            "run past the wall-clock timeout",
            P_CPUSPIN,
            chk_timeout_enforced,
            wall_override=4.0,
            evidence="observed",
        ),
        Attack(
            "time_bomb",
            "process",
            "spawn a detached child, then spin until the wall-clock timeout kills the program",
            "keep a process acting after the timeout killed the program",
            P_TIMEBOMB,
            chk_outlives_run,
            wall_override=4.0,
            outlives_run=True,
            evidence="observed",
        ),
        Attack(
            "orphan_survivor",
            "process",
            "spawn a detached child, then exit normally",
            "leave a process running after the run returns",
            P_ORPHAN,
            chk_outlives_run,
            outlives_run=True,
            evidence="observed",
        ),
        Attack(
            "output_flood",
            "resource",
            "write ~50 MB to stdout",
            "flood the harness's captured output",
            P_OUTPUTFLOOD,
            chk_output_flood,
            evidence="observed",
        ),
    ]
