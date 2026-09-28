"""Subprocess backend: runs code as a bare child process on the host.

This is the *unsafe baseline*: it exists to be beaten, never to contain anything. What it
enforces:

* everywhere: the wall-clock timeout (the process tree is killed) and the per-stream output
  cap (the tree is killed once a stream passes it);
* on POSIX only: ``RLIMIT_AS`` (memory), ``RLIMIT_FSIZE`` and ``RLIMIT_NOFILE``, set in the
  child before exec. Windows has no equivalent here, so those limits are not enforced there.

It never enforces pids or cpu limits and has no workspace size cap. It inherits the host
environment on purpose: a real "just run the code" harness does.

Out-of-memory is not observable from outside a plain child process (an ``RLIMIT_AS`` failure
surfaces only as the program's own ``MemoryError``, which it could print regardless), so
``RunResult.out_of_memory`` is always ``None`` (unknown) for this backend.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from ..profiles import Profile
from ..types import PROGRAM_FILE, RunResult, RunSpec
from .base import read_files_out, run_capped

# Limits this backend actually enforces on the current OS (see module docstring).
ENFORCED_LIMITS: tuple[str, ...] = (
    ("wall_seconds", "output_bytes", "memory_bytes", "fsize_bytes", "nofile")
    if os.name == "posix"
    else ("wall_seconds", "output_bytes")
)


class SubprocessBackend:
    name = "subprocess"

    def available(self) -> bool:
        return True  # needs nothing beyond this interpreter; mirrors DockerBackend.available

    def run(self, spec: RunSpec, profile: Profile) -> RunResult:
        workdir = Path(tempfile.mkdtemp(prefix="agsbx-sub-"))
        try:
            return self._run_in(workdir, spec, profile)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def _run_in(self, workdir: Path, spec: RunSpec, profile: Profile) -> RunResult:
        for rel, content in spec.files_in.items():
            dest = workdir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)

        if spec.code is not None:
            (workdir / PROGRAM_FILE).write_bytes(spec.code.encode("utf-8"))
            argv = [sys.executable, "-u", str(workdir / PROGRAM_FILE)]
        else:
            assert spec.argv is not None
            argv = list(spec.argv)

        env = dict(os.environ)  # unsafe baseline inherits everything
        env.update(spec.env)

        popen_kwargs: dict[str, object] = {"cwd": str(workdir), "env": env}
        if os.name == "posix":
            popen_kwargs["preexec_fn"] = _posix_limits(spec)
        elif os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        cap = run_capped(
            argv,
            stdin=spec.stdin.encode("utf-8"),
            output_bytes=spec.limits.output_bytes,
            deadline_s=spec.limits.wall_seconds,
            kill=lambda proc: _kill_tree(proc.pid),
            **popen_kwargs,
        )
        return RunResult(
            backend=self.name,
            profile=profile.name,
            exit_code=None if cap.deadline_hit else cap.exit_code,
            stdout=cap.stdout,
            stderr=cap.stderr,
            duration_s=cap.seconds,
            timed_out=cap.deadline_hit,
            out_of_memory=None,
            output_truncated=cap.output_truncated,
            files_out=read_files_out(workdir, spec.files_out),
            argv=tuple(argv),
            program_s=cap.seconds,
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
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                timeout=15,
            )
    else:  # pragma: no cover - not exercised on Windows CI
        with contextlib.suppress(ProcessLookupError):
            os.killpg(os.getpgid(pid), signal.SIGKILL)
