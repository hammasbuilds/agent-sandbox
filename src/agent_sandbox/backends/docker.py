"""Docker backend: runs a spec inside a container under a hardening profile.

Every container is labelled ``agent-sandbox=1`` and given a unique name so the harness
only ever kills or removes containers it created. Files go in and out through a
host temp directory bind-mounted at ``/work`` (writable even under a read-only rootfs,
because a bind mount overrides it -- the read-only rootfs still protects ``/``, ``/etc``,
``/usr`` and everything else).
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from ..profiles import Profile
from ..types import RunResult, RunSpec
from .base import read_files_out, truncate
from .docker_cmd import build_run_argv

DEFAULT_IMAGE = "python:3.12-slim"
# Extra seconds allowed for Docker's own container start-up on top of the code's budget.
# On a busy host a cold `docker run` can take 10s+ before the code even executes; without
# this grace those seconds would be misread as the code timing out.
STARTUP_GRACE_S = 40.0


def _fmt_seconds(v: float) -> str:
    return f"{v:.3f}".rstrip("0").rstrip(".")


class DockerBackend:
    name = "docker"

    def __init__(self, image: str = DEFAULT_IMAGE) -> None:
        self.image = image
        self._available_cache: bool | None = None

    def available(self) -> bool:
        # Cache a positive result: on a busy host the daemon can be slow, and re-probing
        # per call both costs seconds and risks a transient timeout flipping the answer.
        if self._available_cache:
            return True
        if not shutil.which("docker"):
            return False
        try:
            r = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        ok = r.returncode == 0 and bool(r.stdout.strip())
        self._available_cache = ok
        return ok

    def run(self, spec: RunSpec, profile: Profile) -> RunResult:
        if profile.backend != "docker":
            raise ValueError(f"profile {profile.name!r} is not a docker profile")

        run_id = uuid.uuid4().hex[:12]
        name = f"agsbx-{run_id}"
        host_work = Path(tempfile.mkdtemp(prefix="agsbx-work-"))
        try:
            return self._run_in(host_work, spec, profile, run_id, name)
        finally:
            shutil.rmtree(host_work, ignore_errors=True)

    def _run_in(
        self,
        host_work: Path,
        spec: RunSpec,
        profile: Profile,
        run_id: str,
        name: str,
    ) -> RunResult:
        # Materialise inputs in the host working dir (bind-mounted at /work).
        for rel, content in spec.files_in.items():
            dest = host_work / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)

        # The code's wall-clock budget is enforced INSIDE the container by coreutils
        # `timeout`, so Docker's own (highly variable, seconds-long) container start-up
        # cannot eat into it. `timeout` exits 124 when it fires. The outer process gets
        # that budget plus a start-up grace as a safety net only.
        wall = spec.limits.wall_seconds
        if spec.code is not None:
            (host_work / "main.py").write_bytes(spec.code.encode("utf-8"))
            payload = ["python", "-u", "/work/main.py"]
        else:
            assert spec.argv is not None
            payload = list(spec.argv)
        inner = ["timeout", _fmt_seconds(wall), *payload]

        argv = build_run_argv(
            image=self.image,
            profile=profile,
            limits=spec.limits,
            container_name=name,
            workdir_mount=str(host_work),
            inner_argv=inner,
            env=spec.env,
            run_id=run_id,
        )

        start = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                argv,
                input=spec.stdin.encode("utf-8"),
                capture_output=True,
                timeout=wall + STARTUP_GRACE_S,
            )
            exit_code: int | None = proc.returncode
            out_raw, err_raw = proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as e:
            timed_out = True
            exit_code = None
            out_raw = e.stdout or b""
            err_raw = e.stderr or b""
            self._kill(name)
        duration = time.monotonic() - start

        if exit_code == 124:  # coreutils timeout fired: the code exceeded its budget
            timed_out = True

        stdout, t1 = truncate(out_raw.decode("utf-8", "replace"), spec.limits.output_bytes)
        stderr, t2 = truncate(err_raw.decode("utf-8", "replace"), spec.limits.output_bytes)

        files_out = read_files_out(host_work, spec.files_out)

        oom = exit_code == 137 or "MemoryError" in stderr

        return RunResult(
            backend=self.name,
            profile=profile.name,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_s=duration,
            timed_out=timed_out,
            out_of_memory=oom,
            output_truncated=t1 or t2,
            files_out=files_out,
            argv=tuple(argv),
        )

    def _kill(self, name: str) -> None:
        # Only ever kills a container this backend created (unique name).
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                ["docker", "kill", name],
                capture_output=True,
                timeout=15,
            )

    def cleanup(self) -> int:
        """Remove any leftover agent-sandbox containers (crash safety). Returns count."""
        try:
            r = subprocess.run(
                ["docker", "ps", "-aq", "--filter", "label=agent-sandbox=1"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            return 0
        ids = [x for x in r.stdout.split() if x]
        if not ids:
            return 0
        subprocess.run(["docker", "rm", "-f", *ids], capture_output=True, timeout=30)
        return len(ids)
