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


@pytest.mark.parametrize("attack_name", ["tcp_egress", "run_as_root", "cap_effective"])
def test_hardened_blocks_key_attacks(sandbox, attack_name):
    by = {a.name: a for a in build_attacks()}
    runner = ChaosRunner(sandbox, reps=1)
    try:
        cell = runner.run_cell(by[attack_name], "hardened")
    finally:
        runner.close()
    assert cell.verdict == "blocked", cell.evidence
