"""Integration tests that need a running Docker engine. Marked `docker` and skipped
automatically when the engine is absent (see conftest)."""

from __future__ import annotations

import _thread
import subprocess
import threading
import time
import uuid

import pytest

from agent_sandbox import RunSpec, Sandbox, limits_for
from agent_sandbox.attacks.registry import build_attacks
from agent_sandbox.chaos import ChaosRunner, canary_candidates

pytestmark = pytest.mark.docker

# Every container these tests create carries this session label, and every lookup or kill
# below filters on it, so a test never touches another process's runs.
SESSION = "pytest-" + uuid.uuid4().hex[:8]
SESSION_LABEL = f"agent-sandbox-session={SESSION}"


@pytest.fixture(scope="module")
def sandbox():
    sb = Sandbox(session=SESSION)
    yield sb
    sb.cleanup()  # this session's leftovers only


def test_trivial_run_hardened(sandbox):
    r = sandbox.run(code="print('hi')", profile="hardened")
    assert r.ok
    assert r.stdout.strip() == "hi"


def test_hardened_runs_as_nobody(sandbox):
    r = sandbox.run(code="import os; print(os.getuid())", profile="hardened")
    assert r.stdout.strip() == "65534"


def test_baseline_runs_as_root(sandbox):
    r = sandbox.run(code="import os; print(os.getuid())", profile="docker-baseline")
    assert r.stdout.strip() == "0"


def test_hardened_rootfs_is_read_only(sandbox):
    code = "open('/etc/x','w').write('y')"
    r = sandbox.run(code=code, profile="hardened")
    assert r.exit_code != 0
    assert "Read-only file system" in r.stderr or "OSError" in r.stderr


def test_fileout_guard_on_linux_bind_mount(tmp_path):
    """On Linux, bind-mount symlinks are real: a naive reader follows ../ out of the
    workdir and leaks the canary; read_files_out must not. Run inside a container so the
    filesystem semantics are Linux's, not the Windows host's."""
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src"
    probe = (
        "import sys, os; sys.path.insert(0, '/src');"
        "from pathlib import Path;"
        "from agent_sandbox.backends.base import read_files_out;"
        "w = Path('/p/work'); w.mkdir(parents=True);"
        "Path('/p/canary.txt').write_text('CANARY');"
        "os.symlink('../canary.txt', w / 'out.txt');"
        "print('NAIVE', (w / 'out.txt').read_text());"
        "print('GUARDED', read_files_out(w, ('out.txt',)))"
    )
    r = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--label",
            "agent-sandbox=1",
            "--label",
            SESSION_LABEL,
            "-v",
            f"{src}:/src:ro",
            "-v",
            f"{tmp_path}:/p",
            "python:3.12-slim",
            "python",
            "-c",
            probe,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert r.returncode == 0, r.stderr
    assert "NAIVE CANARY" in r.stdout  # the attack is real on Linux
    assert "GUARDED {}" in r.stdout  # and the guard refuses it


def _names(all_states: bool = False) -> set[str]:
    """Names of THIS test session's containers (never another process's)."""
    argv = ["docker", "ps", "--filter", f"label={SESSION_LABEL}", "--format", "{{.Names}}"]
    if all_states:
        argv.insert(2, "-a")
    return set(subprocess.run(argv, capture_output=True, text=True, timeout=60).stdout.split())


SIGTERM_IGNORER = (
    "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(60)\n"
)


@pytest.mark.parametrize("profile", ["docker-baseline", "hardened"])
def test_sigterm_ignoring_program_is_killed_within_budget(sandbox, profile):
    wall = 3.0
    r = sandbox.run(
        code=SIGTERM_IGNORER, profile=profile, limits=limits_for(profile).with_(wall_seconds=wall)
    )
    assert r.timed_out
    assert r.exit_code == 137  # SIGKILL from `timeout -k` after SIGTERM was ignored
    # budget + 2 s kill-after + a few seconds of `docker exec` overhead (was 44.9 s)
    assert r.program_s is not None and r.program_s < wall + 2 + 6
    assert r.duration_s < wall + 2 + 30


def test_program_exiting_124_itself_is_not_a_timeout(sandbox):
    r = sandbox.run(code="import sys; sys.exit(124)", profile="hardened")
    assert r.exit_code == 124
    assert not r.timed_out


def test_oom_comes_from_docker_state_not_program_output(sandbox):
    real = sandbox.run(code="a = bytearray(300 << 20)", profile="hardened")
    assert real.out_of_memory is True
    fake = sandbox.run(
        code="import sys; print('MemoryError', file=sys.stderr); sys.exit(137)",
        profile="hardened",
    )
    assert "MemoryError" in fake.stderr
    assert fake.out_of_memory is False


@pytest.mark.parametrize("profile", ["docker-baseline", "hardened"])
def test_output_flood_is_capped_and_killed(sandbox, profile):
    lim = limits_for(profile).with_(wall_seconds=30.0)
    r = sandbox.run(
        code="import sys\nwhile True: sys.stdout.write('A' * 65536)", profile=profile, limits=lim
    )
    assert r.output_truncated
    assert not r.timed_out  # stopped by the cap, not the 30 s clock
    assert r.exit_code == 137  # killed at the cap (seconds vary with host load, so not asserted)
    assert len(r.stdout) <= lim.output_bytes + 20


def test_hardened_workspace_is_size_capped(sandbox):
    cap = limits_for("hardened").workspace_bytes
    code = (
        "import sys\n"
        "total = 0\n"
        "try:\n"
        "    for i in range(20):\n"  # 20 x 6 MB: each file under the 8 MB fsize ulimit
        "        with open(f'f{i}', 'wb') as f:\n"
        "            f.write(b'x' * (6 << 20))\n"
        "        total += 6 << 20\n"
        "except OSError as e:\n"
        "    print('STOPPED', total, e.errno)\n"
        "    sys.exit(3)\n"
        "print('WROTE', total)\n"
    )
    r = sandbox.run(code=code, profile="hardened")
    assert r.exit_code == 3, r.stdout + r.stderr
    words = r.stdout.split()
    assert words[0] == "STOPPED"
    assert int(words[1]) <= cap
    assert words[2] == "28"  # ENOSPC: the tmpfs is full, not a ulimit


def test_hardened_files_in_and_out_through_the_tmpfs(sandbox):
    code = (
        "import os\n"
        "os.makedirs('out', exist_ok=True)\n"
        "data = open('data/in.txt').read()\n"
        "open('out/r.txt', 'w').write(data.upper())\n"
        "os.symlink('/etc/passwd', 'leak.txt')\n"
    )
    r = sandbox.run(
        code=code,
        profile="hardened",
        files_in={"data/in.txt": b"abc"},
        files_out=("out/r.txt", "leak.txt", "missing.txt"),
    )
    assert r.ok, r.stderr
    assert r.files_out == {"out/r.txt": b"ABC"}  # the symlink and the missing file are dropped


def test_interrupted_run_leaves_no_container(sandbox):
    before = _names(all_states=True)
    seen: set[str] = set()

    def interrupt_when_container_runs():
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            new = _names() - before
            if new:
                seen.update(new)
                time.sleep(1.0)
                _thread.interrupt_main()
                return
            time.sleep(0.3)

    threading.Thread(target=interrupt_when_container_runs, daemon=True).start()
    with pytest.raises(KeyboardInterrupt):
        sandbox.run(
            code="import time; time.sleep(60)",
            profile="hardened",
            limits=limits_for("hardened").with_(wall_seconds=60),
        )
    assert seen, "the run's container was never observed"
    assert not (seen & _names(all_states=True)), "an interrupted run left its container behind"


def test_container_stopped_from_outside_is_an_error_not_output(sandbox):
    before = _names(all_states=True)

    def kill_our_container():
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            new = _names() - before
            if new:
                time.sleep(2.0)
                for n in new:  # only this session's new container: the run below
                    subprocess.run(["docker", "kill", n], capture_output=True, timeout=60)
                return
            time.sleep(0.3)

    threading.Thread(target=kill_our_container, daemon=True).start()
    r = sandbox.run(
        code="import time; time.sleep(30); print('done')",
        profile="hardened",
        limits=limits_for("hardened").with_(wall_seconds=40),
    )
    assert r.error is not None and "stopped from outside" in r.error
    assert not r.ok
    assert not r.out_of_memory


@pytest.mark.parametrize("attack_name", ["tcp_egress", "run_as_root", "cap_effective"])
def test_hardened_blocks_key_attacks(sandbox, attack_name):
    by = {a.name: a for a in build_attacks()}
    runner = ChaosRunner(sandbox, reps=1)
    try:
        cell = runner.run_cell(by[attack_name], "hardened")
    finally:
        runner.close()
    assert cell.verdict == "blocked", cell.evidence


def test_cleanup_leaves_other_sessions_alone(sandbox):
    other = "pytest-other-" + uuid.uuid4().hex[:8]
    name = f"agsbx-{other}"
    subprocess.run(
        [
            "docker", "run", "--detach", "--name", name, "--label", "agent-sandbox=1",
            "--label", f"agent-sandbox-session={other}", "--network", "none",
            "python:3.12-slim", "sleep", "120",
        ],
        capture_output=True, check=True, timeout=120,
    )  # fmt: skip
    try:
        sandbox.cleanup()  # our own session
        sandbox.remove_stopped()  # stopped containers only; the other one is running
        alive = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"name=^{name}$"],
            capture_output=True, text=True, timeout=60,
        )  # fmt: skip
        assert alive.stdout.strip(), "a cleanup removed another session's live container"
    finally:
        assert Sandbox(session=other).cleanup() == 1  # removed by its own session label


ORPHAN = (
    "import os, subprocess, sys\n"
    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
    "start_new_session=True)\n"
)


@pytest.mark.parametrize("profile", ["docker-baseline", "hardened"])
def test_lingering_processes_are_counted_before_teardown(sandbox, profile):
    left = sandbox.run_spec(RunSpec(code=ORPHAN, count_lingering=True), profile)
    assert left.ok, left.stderr
    assert left.lingering_processes == 1  # the detached sleeper, alive at program exit
    clean = sandbox.run_spec(RunSpec(code="print(1)", count_lingering=True), profile)
    assert clean.lingering_processes == 0
    assert sandbox.run(code="print(1)", profile=profile).lingering_processes is None


def test_host_canary_payload_finds_a_host_mount_when_one_is_exposed(tmp_path):
    """Positive control for host_canary_read: if the host drive WERE mounted where Docker
    Desktop keeps it, the payload's candidate paths would find the canary. Without the
    mount (every real profile), they find nothing."""
    import os

    by = {a.name: a for a in build_attacks()}
    canary = tmp_path / "canary.txt"
    canary.write_text("TOKEN-42")
    cands = canary_candidates(str(canary), "docker")
    if len(cands) == 1:
        pytest.skip("host path has no drive letter; the Docker Desktop paths do not apply")
    mount_at = cands[1].rsplit("/", 1)[0]
    base = [
        "docker", "run", "--rm", "--label", "agent-sandbox=1", "--label", SESSION_LABEL,
        "--env", "SBX_CANARY_PATHS=" + "\n".join(cands),
    ]  # fmt: skip
    code = ["python:3.12-slim", "python", "-c", by["host_canary_read"].code]
    exposed = subprocess.run(
        [*base, "-v", f"{tmp_path}:{mount_at}:ro", *code],
        capture_output=True, text=True, timeout=300,
    )  # fmt: skip
    assert "TOKEN-42" in exposed.stdout, exposed.stdout + exposed.stderr
    hidden = subprocess.run([*base, *code], capture_output=True, text=True, timeout=300)
    assert "TOKEN-42" not in hidden.stdout
    assert os.path.exists(canary)
