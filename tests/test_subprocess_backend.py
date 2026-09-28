"""The subprocess backend runs real host processes; these tests need no Docker and no
network, only the local Python interpreter."""

from __future__ import annotations

import os
from pathlib import Path

from agent_sandbox.backends.base import read_files_out
from agent_sandbox.backends.subprocess_backend import SubprocessBackend
from agent_sandbox.profiles import SUBPROCESS
from agent_sandbox.types import Limits, RunSpec


def _run(code, **kw):
    spec = RunSpec(code=code, limits=Limits(wall_seconds=kw.pop("wall", 10.0)), **kw)
    return SubprocessBackend().run(spec, SUBPROCESS)


def test_captures_stdout_and_exit():
    r = _run("print('hello'); import sys; sys.exit(0)")
    assert r.stdout.strip() == "hello"
    assert r.exit_code == 0
    assert r.ok


def test_nonzero_exit_is_reported():
    r = _run("import sys; sys.exit(7)")
    assert r.exit_code == 7
    assert not r.ok


def test_stdin_is_delivered():
    r = RunSpec(code="import sys; print(sys.stdin.read().upper())", stdin="abc")
    out = SubprocessBackend().run(r, SUBPROCESS)
    assert out.stdout.strip() == "ABC"


def test_env_override_visible():
    spec = RunSpec(code="import os; print(os.environ['MY_FLAG'])", env={"MY_FLAG": "ZZ"})
    r = SubprocessBackend().run(spec, SUBPROCESS)
    assert r.stdout.strip() == "ZZ"


def test_timeout_kills_and_flags():
    r = _run("import time; time.sleep(30)", wall=1.0)
    assert r.timed_out
    assert r.exit_code is None
    assert r.duration_s < 10


def test_files_in_and_out_roundtrip():
    spec = RunSpec(
        code="open('out.txt','w').write(open('in.txt').read()[::-1])",
        files_in={"in.txt": b"abcd"},
        files_out=("out.txt",),
    )
    r = SubprocessBackend().run(spec, SUBPROCESS)
    assert r.files_out["out.txt"] == b"dcba"


def test_output_flood_is_capped_and_killed():
    spec = RunSpec(
        code="import sys\nwhile True: sys.stdout.write('A' * 65536)",
        limits=Limits(wall_seconds=30.0, output_bytes=1 << 20),
    )
    r = SubprocessBackend().run(spec, SUBPROCESS)
    assert r.output_truncated
    assert not r.timed_out  # killed for the output cap, well before the 30 s budget
    assert r.duration_s < 20
    assert len(r.stdout) <= (1 << 20) + 20


def test_out_of_memory_is_unknown_not_read_from_program_output():
    r = _run("import sys; print('MemoryError', file=sys.stderr); sys.exit(1)")
    assert "MemoryError" in r.stderr
    assert r.out_of_memory is None  # not observable here; never inferred from stderr
    assert "OOM" not in r.summary()


def test_read_files_out_refuses_escape(tmp_path: Path):
    (tmp_path / "good.txt").write_bytes(b"ok")
    outside = tmp_path.parent / "secret.txt"
    outside.write_bytes(b"SECRET")
    got = read_files_out(tmp_path, ("good.txt", "../secret.txt"))
    assert got == {"good.txt": b"ok"}


def test_read_files_out_refuses_symlink(tmp_path: Path):
    target = tmp_path.parent / "host_secret.txt"
    target.write_bytes(b"HOSTSECRET")
    link = tmp_path / "out.txt"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        return  # symlink creation not permitted here; guard still covered above
    got = read_files_out(tmp_path, ("out.txt",))
    assert "out.txt" not in got
