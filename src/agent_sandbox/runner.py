"""The public run API: pick a backend for a profile, apply its safety limits, execute.

Resource limits are treated as a *host-safety floor* attached to each profile, not as
part of the isolation claim being tested. Even the ``default`` profile therefore runs
with a generous memory/pids/fsize cap and a wall-clock timeout, purely so a resource
bomb in the suite cannot take down the machine running it. This is stated in the README;
a genuinely naked ``docker run`` would omit them. The *isolation* differences (network,
capabilities, user, rootfs, /proc, seccomp) are what distinguish the profiles, and those
are applied exactly as the profile declares.
"""

from __future__ import annotations

from .backends.docker import DEFAULT_IMAGE, DockerBackend
from .backends.subprocess_backend import SubprocessBackend
from .profiles import get_profile
from .types import Limits, RunResult, RunSpec

_MB = 1 << 20

# Host-safety limits per profile. Hardened is tight; default is a loose floor that still
# protects the host; subprocess gets a wall timeout only (POSIX rlimits when available).
PROFILE_LIMITS: dict[str, Limits] = {
    "subprocess": Limits(wall_seconds=10.0, memory_bytes=512 * _MB, fsize_bytes=64 * _MB),
    "default": Limits(
        wall_seconds=10.0,
        memory_bytes=512 * _MB,
        cpus=2.0,
        pids=512,
        nofile=1024,
        fsize_bytes=64 * _MB,
    ),
    "hardened": Limits(
        wall_seconds=10.0,
        memory_bytes=128 * _MB,
        cpus=1.0,
        pids=64,
        nofile=256,
        fsize_bytes=8 * _MB,
    ),
}


def limits_for(profile_name: str) -> Limits:
    return PROFILE_LIMITS[profile_name]


class Sandbox:
    """Entry point. Holds one backend per kind and routes by profile."""

    def __init__(self, image: str = DEFAULT_IMAGE) -> None:
        self._docker = DockerBackend(image=image)
        self._subprocess = SubprocessBackend()

    @property
    def image(self) -> str:
        return self._docker.image

    def docker_available(self) -> bool:
        return self._docker.available()

    def run(
        self,
        *,
        code: str | None = None,
        argv: tuple[str, ...] | None = None,
        profile: str = "hardened",
        stdin: str = "",
        env: dict[str, str] | None = None,
        files_in: dict[str, bytes] | None = None,
        files_out: tuple[str, ...] = (),
        limits: Limits | None = None,
    ) -> RunResult:
        prof = get_profile(profile)
        spec = RunSpec(
            code=code,
            argv=argv,
            stdin=stdin,
            env=env or {},
            files_in=files_in or {},
            files_out=files_out,
            limits=limits or limits_for(profile),
        )
        if prof.backend == "docker":
            if not self._docker.available():
                return RunResult(
                    backend="docker",
                    profile=profile,
                    exit_code=None,
                    stdout="",
                    stderr="",
                    duration_s=0.0,
                    timed_out=False,
                    error="docker engine unavailable",
                )
            return self._docker.run(spec, prof)
        return self._subprocess.run(spec, prof)

    def run_spec(self, spec: RunSpec, profile: str) -> RunResult:
        prof = get_profile(profile)
        if prof.backend == "docker":
            return self._docker.run(spec, prof)
        return self._subprocess.run(spec, prof)

    def cleanup(self) -> int:
        return self._docker.cleanup()
