"""Integration tests that need a running Docker engine. Marked `docker` and skipped
automatically when the engine is absent (see conftest)."""

from __future__ import annotations

import pytest

from agent_sandbox import Sandbox
from agent_sandbox.attacks.registry import build_attacks
from agent_sandbox.chaos import ChaosRunner

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def sandbox():
    return Sandbox()


def test_trivial_run_hardened(sandbox):
    r = sandbox.run(code="print('hi')", profile="hardened")
    assert r.ok
    assert r.stdout.strip() == "hi"


def test_hardened_runs_as_nobody(sandbox):
    r = sandbox.run(code="import os; print(os.getuid())", profile="hardened")
    assert r.stdout.strip() == "65534"


def test_default_runs_as_root(sandbox):
    r = sandbox.run(code="import os; print(os.getuid())", profile="default")
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
    import subprocess
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
        ["docker", "run", "--rm", "--label", "agent-sandbox=1",
         "-v", f"{src}:/src:ro", "-v", f"{tmp_path}:/p",
         "python:3.12-slim", "python", "-c", probe],
        capture_output=True, text=True, timeout=300,
    )
    assert r.returncode == 0, r.stderr
    assert "NAIVE CANARY" in r.stdout  # the attack is real on Linux
    assert "GUARDED {}" in r.stdout  # and the guard refuses it


@pytest.mark.parametrize("attack_name", ["tcp_egress", "run_as_root", "cap_effective"])
def test_hardened_blocks_key_attacks(sandbox, attack_name):
    by = {a.name: a for a in build_attacks()}
    runner = ChaosRunner(sandbox, reps=1)
    try:
        cell = runner.run_cell(by[attack_name], "hardened")
    finally:
        runner.close()
    assert cell.verdict == "blocked", cell.evidence
