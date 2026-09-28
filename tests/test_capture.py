"""Bounded output capture (run_capped): real child processes, no Docker, no network."""

from __future__ import annotations

import _thread
import sys
import threading
import time

import pytest

from agent_sandbox.backends.base import TRUNCATION_MARK, run_capped
from agent_sandbox.backends.subprocess_backend import _kill_tree


def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def _run(code: str, cap: int = 1000, deadline: float = 20.0, kills: list | None = None):
    def kill(proc):
        if kills is not None:
            kills.append(proc.pid)
        _kill_tree(proc.pid)

    return run_capped(_py(code), stdin=b"", output_bytes=cap, deadline_s=deadline, kill=kill)


def test_small_output_is_complete_and_not_flagged():
    c = _run("import sys; sys.stdout.write('x' * 1000); sys.stderr.write('e')", cap=1000)
    assert c.stdout == "x" * 1000  # exactly at the cap is not truncation
    assert c.stderr == "e"
    assert not c.output_truncated
    assert c.exit_code == 0


def test_endless_output_is_capped_and_the_process_killed():
    kills: list[int] = []
    t = time.monotonic()
    c = _run("import sys\nwhile True: sys.stdout.write('A' * 65536)", cap=100_000, kills=kills)
    assert c.output_truncated
    assert kills, "the harness must kill a program that overflows the cap"
    assert c.stdout.endswith(TRUNCATION_MARK)
    assert len(c.stdout) == 100_000 + len(TRUNCATION_MARK)
    assert time.monotonic() - t < 15
    assert not c.deadline_hit


def test_cap_applies_to_stderr_too():
    c = _run("import sys\nwhile True: sys.stderr.write('E' * 65536)", cap=50_000)
    assert c.output_truncated
    assert len(c.stderr) == 50_000 + len(TRUNCATION_MARK)


def test_deadline_kills():
    c = _run("import time; time.sleep(60)", deadline=1.0)
    assert c.deadline_hit
    assert c.seconds < 15


def test_stdin_is_delivered():
    c = run_capped(
        _py("import sys; print(sys.stdin.read()[::-1])"),
        stdin=b"abc",
        output_bytes=100,
        deadline_s=20,
        kill=lambda p: _kill_tree(p.pid),
    )
    assert c.stdout.strip() == "cba"


def test_keyboard_interrupt_kills_the_process(tmp_path):
    beat = tmp_path / "beat"
    code = (
        "import time, pathlib\n"
        f"p = pathlib.Path({str(beat)!r})\n"
        "i = 0\n"
        "while True:\n"
        "    i += 1; p.write_text(str(i)); time.sleep(0.05)\n"
    )
    kills: list[int] = []

    def interrupt_once_running():
        deadline = time.monotonic() + 20
        while not beat.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        _thread.interrupt_main()

    threading.Thread(target=interrupt_once_running, daemon=True).start()
    with pytest.raises(KeyboardInterrupt):
        _run(code, deadline=60, kills=kills)
    assert kills, "an interrupted run must kill what it launched"
    time.sleep(1.0)
    before = beat.read_text()
    time.sleep(1.0)
    assert beat.read_text() == before, "the program kept running after the interrupt"
