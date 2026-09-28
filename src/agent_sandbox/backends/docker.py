"""Docker backend: runs a spec inside a container under a hardening profile.

Every container is labelled ``agent-sandbox=1``, ``agent-sandbox-run=<run id>`` and
``agent-sandbox-session=<session id>`` and given a unique name. The harness kills or removes
a container only by its own unique name, or by its own session label, so it never touches
another process's runs. A run is:

1. ``docker run --detach`` a container with the profile's flags and limits, idling on
   ``sleep`` (see ``docker_cmd``);
2. ``docker exec`` the program in it under ``timeout -k``, streaming stdout/stderr with a
   byte cap (the container is killed if the program exceeds it);
3. read Docker's ``OOMKilled`` state, optionally count the processes the program left
   behind, and copy the requested output files out;
4. ``docker rm --force`` the container -- in a ``finally``, so an exception or Ctrl-C at
   any point still removes it.

Files go in through a host temp directory. Without a workspace cap it is bind-mounted
read-write at ``/work``. With ``Limits.workspace_bytes`` (the ``hardened`` profile), /work is
a size-capped tmpfs: inputs are copied in from a read-only bind at /in, and output files
are copied out with ``tar`` through ``docker exec``, so a program cannot fill the host disk.
"""

from __future__ import annotations

import contextlib
import io
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

from ..profiles import Profile
from ..types import PROGRAM_FILE, RunResult, RunSpec
from .base import Captured, read_files_out, run_capped
from .docker_cmd import (
    KILL_AFTER_S,
    LABEL,
    SESSION_LABEL,
    WORKDIR,
    build_exec_argv,
    build_run_argv,
)

DEFAULT_IMAGE = "python:3.12-slim"
# Seconds allowed for `docker run --detach` to create and start the container. On a busy
# host a cold start can take 10 s+; this is separate from the program's own budget.
STARTUP_TIMEOUT_S = 90.0
# Extra seconds for the `docker exec` round trip on top of budget + kill-after, before the
# harness stops waiting and kills the container itself (a safety net only).
EXEC_GRACE_S = 20.0
_DOCKER_CALL_TIMEOUT_S = 60.0
# Run inside the container after the program exits: counts live processes other than PID 1
# (the idle `sleep`) and itself. Zombies are not counted: they are already dead.
_COUNT_LIVE = (
    "import os\n"
    "me = os.getpid(); n = 0\n"
    "for p in os.listdir('/proc'):\n"
    "    if p.isdigit() and int(p) not in (1, me):\n"
    "        try:\n"
    "            state = open(f'/proc/{p}/stat').read().rsplit(')', 1)[1].split()[0]\n"
    "        except OSError:\n"
    "            continue\n"
    "        n += state != 'Z'\n"
    "print(n)\n"
)


class PreflightError(RuntimeError):
    """The image cannot run sandboxed code (missing, or lacks what the backend needs)."""


class DockerBackend:
    name = "docker"

    def __init__(self, image: str = DEFAULT_IMAGE, session: str | None = None) -> None:
        self.image = image
        # Unique per backend unless given: labels every container this backend creates.
        self.session = session or uuid.uuid4().hex[:12]
        self._available_cache: bool | None = None
        self._preflight_ok = False

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

    def preflight(self) -> None:
        """Make sure the image is present and has what a run needs; raise PreflightError.

        Pulls the image if it is missing (so a first run, or a benchmark, never times a
        pull), then checks the image has ``sleep`` and a ``timeout`` that supports ``-k``:
        without them the wall-clock budget could not be enforced. Done once per backend.
        """
        if self._preflight_ok:
            return
        have = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", self.image],
            capture_output=True,
            timeout=_DOCKER_CALL_TIMEOUT_S,
        )
        if have.returncode != 0:
            pull = subprocess.run(["docker", "pull", self.image], capture_output=True, timeout=1800)
            if pull.returncode != 0:
                err = pull.stderr.decode("utf-8", "replace").strip()
                raise PreflightError(f"could not pull image {self.image!r}: {err}")
        probe = subprocess.run(
            [
                "docker", "run", "--rm", "--network", "none", "--label", f"{LABEL}=1",
                "--label", f"{SESSION_LABEL}={self.session}",
                self.image, "timeout", "-k", "1", "5", "sleep", "0",
            ],
            capture_output=True,
            timeout=STARTUP_TIMEOUT_S,
        )  # fmt: skip
        if probe.returncode != 0:
            err = probe.stderr.decode("utf-8", "replace").strip()
            raise PreflightError(
                f"image {self.image!r} cannot enforce the wall-clock budget: it needs "
                f"coreutils `timeout` (with -k) and `sleep` on PATH "
                f"(probe exit {probe.returncode}: {err or 'no output'})"
            )
        self._preflight_ok = True

    def run(self, spec: RunSpec, profile: Profile) -> RunResult:
        if profile.backend != "docker":
            raise ValueError(f"profile {profile.name!r} is not a docker profile")
        try:
            self.preflight()
        except (PreflightError, OSError, subprocess.TimeoutExpired) as e:
            return _error_result(profile, f"preflight failed: {e}")

        run_id = uuid.uuid4().hex[:12]
        name = f"agsbx-{run_id}"
        host_work = Path(tempfile.mkdtemp(prefix="agsbx-work-"))
        try:
            return self._run_in(host_work, spec, profile, run_id, name)
        except BaseException:
            self._kill(name)
            raise
        finally:
            self._remove(name)
            shutil.rmtree(host_work, ignore_errors=True)

    def _run_in(
        self,
        host_work: Path,
        spec: RunSpec,
        profile: Profile,
        run_id: str,
        name: str,
    ) -> RunResult:
        limits = spec.limits
        # Materialise inputs in the host working dir.
        inputs = dict(spec.files_in)
        if spec.code is not None:
            inputs[PROGRAM_FILE] = spec.code.encode("utf-8")
            payload = ["python", "-u", f"{WORKDIR}/{PROGRAM_FILE}"]
        else:
            assert spec.argv is not None
            payload = list(spec.argv)
        if limits.workspace_bytes is not None:
            total = sum(len(v) for v in inputs.values())
            if total > limits.workspace_bytes:
                return _error_result(
                    profile,
                    f"inputs total {total} bytes, more than the {limits.workspace_bytes}-byte "
                    "workspace",
                )
        for rel, content in inputs.items():
            dest = host_work / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)

        wall = limits.wall_seconds
        start = time.monotonic()
        run_argv = build_run_argv(
            image=self.image,
            profile=profile,
            limits=limits,
            container_name=name,
            host_workdir=str(host_work),
            keepalive_s=wall + KILL_AFTER_S + EXEC_GRACE_S + 60,
            env=spec.env,
            run_id=run_id,
            session=self.session,
        )
        try:
            started = subprocess.run(run_argv, capture_output=True, timeout=STARTUP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            return _error_result(
                profile, f"container did not start within {STARTUP_TIMEOUT_S:.0f}s", run_argv
            )
        if started.returncode != 0:
            err = started.stderr.decode("utf-8", "replace").strip()
            return _error_result(profile, f"docker run failed: {err}", run_argv)

        exec_argv = build_exec_argv(
            container_name=name,
            payload=payload,
            wall_seconds=wall,
            copy_inputs=limits.workspace_bytes is not None,
        )
        cap = run_capped(
            exec_argv,
            stdin=spec.stdin.encode("utf-8"),
            output_bytes=limits.output_bytes,
            deadline_s=wall + KILL_AFTER_S + EXEC_GRACE_S,
            kill=lambda _proc: self._kill(name),
        )
        running, oom = self._state(name)
        killed_by_harness = cap.deadline_hit or cap.output_truncated
        # PID 1 is `sleep`, which ignores signals sent from inside the container, so the
        # program cannot stop its own container. Stopped with no OOM and no harness kill
        # means something outside stopped it; the result would be meaningless.
        error = None
        if running is False and not oom and not killed_by_harness:
            error = (
                "container stopped during the run without an OOM kill or a harness kill "
                "(stopped from outside?); the output is not the program's"
            )
        lingering = self._count_live(name) if spec.count_lingering and running else None
        if limits.workspace_bytes is not None and running:
            files_out = self._copy_out(name, spec.files_out)
        elif limits.workspace_bytes is not None:
            files_out = {}  # the tmpfs went with the container
        else:
            files_out = read_files_out(host_work, spec.files_out)
        return RunResult(
            error=error,
            backend=self.name,
            profile=profile.name,
            exit_code=cap.exit_code,
            stdout=cap.stdout,
            stderr=cap.stderr,
            duration_s=time.monotonic() - start,
            timed_out=_timed_out(cap, oom, wall),
            out_of_memory=oom,
            output_truncated=cap.output_truncated,
            files_out=files_out,
            argv=tuple(run_argv),
            program_s=cap.seconds,
            lingering_processes=lingering,
        )

    def _count_live(self, name: str) -> int | None:
        """Processes still alive in the container besides its idle PID 1, before teardown."""
        try:
            r = subprocess.run(
                ["docker", "exec", name, "python", "-c", _COUNT_LIVE],
                capture_output=True,
                text=True,
                timeout=_DOCKER_CALL_TIMEOUT_S,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        out = r.stdout.strip()
        return int(out) if r.returncode == 0 and out.isdigit() else None

    def _state(self, name: str) -> tuple[bool | None, bool]:
        """(still running, OOM-killed) from Docker's own record, never the program's output.

        ``running`` is None when the state could not be read.
        """
        try:
            r = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}} {{.State.OOMKilled}}", name],
                capture_output=True,
                text=True,
                timeout=_DOCKER_CALL_TIMEOUT_S,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None, False
        fields = r.stdout.split()
        if r.returncode != 0 or len(fields) != 2:
            return None, False
        return fields[0] == "true", fields[1] == "true"

    def _copy_out(self, name: str, names: tuple[str, ...]) -> dict[str, bytes]:
        """Copy requested regular files out of the tmpfs /work via ``tar`` in the container.

        The host never follows anything: only tar members that are regular files with
        exactly a requested name are kept, so a symlink planted at an output path is
        dropped. The data is bounded by the workspace size.
        """
        if not names:
            return {}
        argv = ["docker", "exec", name, "tar", "-c", "--no-recursion", "-f", "-", "-C", WORKDIR]
        try:
            r = subprocess.run(
                [*argv, "--", *names], capture_output=True, timeout=_DOCKER_CALL_TIMEOUT_S
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}
        wanted = set(names)
        out: dict[str, bytes] = {}
        with (
            contextlib.suppress(tarfile.TarError),
            tarfile.open(fileobj=io.BytesIO(r.stdout), mode="r:") as tar,
        ):
            for member in tar:
                if member.name in wanted and member.isreg():
                    f = tar.extractfile(member)
                    if f is not None:
                        out[member.name] = f.read()
        return out

    def _kill(self, name: str) -> None:
        # Only ever kills a container this backend created (unique name).
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(["docker", "kill", name], capture_output=True, timeout=30)

    def _remove(self, name: str) -> None:
        # Only ever removes a container this backend created (unique name).
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=60)

    def cleanup(self, session: str | None = None) -> int:
        """Remove every container (any state) of one session -- this backend's by default.

        Used for crash safety by the process that owns the session. Raises RuntimeError if
        the engine cannot be queried, so a caller never mistakes "Docker is down" for
        "nothing to clean up".
        """
        label = f"label={SESSION_LABEL}={session or self.session}"
        return self._remove_matching(["--filter", label])

    def remove_stopped(self) -> int:
        """Remove agent-sandbox containers of any session that have already stopped.

        A live run's container is always running (it idles on ``sleep`` until removed), so
        this never disturbs a run in progress elsewhere. A container left by a harness that
        died stops by itself when its keep-alive expires, and is removed here after that.
        """
        return self._remove_matching(
            ["--filter", f"label={LABEL}=1", "--filter", "status=exited", "--filter", "status=dead"]
        )

    def _remove_matching(self, filters: list[str]) -> int:
        try:
            r = subprocess.run(
                ["docker", "ps", "-aq", *filters],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise RuntimeError(f"could not list containers: {e}") from None
        if r.returncode != 0:
            raise RuntimeError(f"could not list containers: {r.stderr.strip()}")
        ids = [x for x in r.stdout.split() if x]
        if not ids:
            return 0
        subprocess.run(["docker", "rm", "-f", *ids], capture_output=True, timeout=60)
        return len(ids)


def _timed_out(cap: Captured, oom: bool, wall: float) -> bool:
    """Whether the wall-clock budget, not the program, ended the run.

    ``timeout`` exits 124 after SIGTERM, or 137 when it had to SIGKILL. A program can exit
    with either code itself, so the code only counts if the program also ran for the
    whole budget as measured by the harness, and it was not an OOM or output-cap kill.
    """
    if cap.deadline_hit:
        return True
    if oom or cap.output_truncated:
        return False
    return cap.exit_code in (124, 137) and cap.seconds >= wall


def _error_result(profile: Profile, error: str, argv: list[str] | None = None) -> RunResult:
    return RunResult(
        backend="docker",
        profile=profile.name,
        exit_code=None,
        stdout="",
        stderr="",
        duration_s=0.0,
        timed_out=False,
        argv=tuple(argv or ()),
        error=error,
    )
