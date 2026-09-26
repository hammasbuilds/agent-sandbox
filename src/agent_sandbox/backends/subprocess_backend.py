"""Subprocess backend: runs code as a bare child process on the host.

This is the *unsafe baseline*. It exists to be beaten. It applies a wall-clock timeout
and, on POSIX, best-effort ``rlimit`` caps; on Windows those rlimits are unavailable, so
resource-exhaustion payloads are only ever run in their self-bounded form (the harness
never launches an unbounded bomb here -- see ``attacks/programs``).

It inherits the host environment on purpose: a real "just run the code" harness does, and
that is exactly the leak the chaos suite measures.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from ..profiles import Profile
from ..types import RunResult, RunSpec
from .base import read_files_out, truncate


class SubprocessBackend:
    name = "subprocess"

    def available(self) -> bool:
        return True

    def run(self, spec: RunSpec, profile: Profile) -> RunResult:
        workdir = Path(tempfile.mkdtemp(prefix="agsbx-sub-"))
        try:
            return self._run_in(workdir, spec, profile)
        finally:
            _rmtree(workdir)

    def _run_in(self, workdir: Path, spec: RunSpec, profile: Profile) -> RunResult:
        for rel, content in spec.files_in.items():
            dest = workdir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)

        if spec.code is not None:
            (workdir / "main.py").write_bytes(spec.code.encode("utf-8"))
            argv = [sys.executable, "-u", str(workdir / "main.py")]
        else:
            assert spec.argv is not None
            argv = list(spec.argv)

        env = dict(os.environ)  # unsafe baseline inherits everything
        env.update(spec.env)

        popen_kwargs: dict[str, object] = {}
        if os.name == "posix":
            popen_kwargs["preexec_fn"] = _posix_limits(spec)  # noqa: PLW1509
        elif os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        start = time.monotonic()
        timed_out = False
        proc = subprocess.Popen(  # noqa: S603
            argv,
            cwd=str(workdir),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **popen_kwargs,  # type: ignore[arg-type]
        )
        try:
            out_raw, err_raw = proc.communicate(
                input=spec.stdin.encode("utf-8"),
                timeout=spec.limits.wall_seconds,
            )
            exit_code: int | None = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = None
            _kill_tree(proc.pid)
            try:
                out_raw, err_raw = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                out_raw, err_raw = b"", b""
        duration = time.monotonic() - start

        stdout, t1 = truncate(out_raw.decode("utf-8", "replace"), spec.limits.output_bytes)
        stderr, t2 = truncate(err_raw.decode("utf-8", "replace"), spec.limits.output_bytes)

        return RunResult(
            backend=self.name,
            profile=profile.name,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_s=duration,
            timed_out=timed_out,
            out_of_memory="MemoryError" in stderr,
            output_truncated=t1 or t2,
            files_out=read_files_out(workdir, spec.files_out),
            argv=tuple(argv),
        )


def _posix_limits(spec: RunSpec):  # pragma: no cover - not exercised on Windows CI
    import resource

    limits = spec.limits

    def apply() -> None:
        if limits.memory_bytes is not None:
            resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        if limits.fsize_bytes is not None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (limits.fsize_bytes, limits.fsize_bytes))
        if limits.nofile is not None:
            resource.setrlimit(resource.RLIMIT_NOFILE, (limits.nofile, limits.nofile))
        os.setsid()

    return apply


def _kill_tree(pid: int) -> None:
    """Kill the process tree rooted at our own launched pid (only that tree)."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            timeout=15,
        )
    else:  # pragma: no cover - not exercised on Windows CI
        import signal

        with contextlib.suppress(ProcessLookupError):
            os.killpg(os.getpgid(pid), signal.SIGKILL)


def _rmtree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)
