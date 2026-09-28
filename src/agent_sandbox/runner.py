"""The public run API: pick a backend for a profile, apply its safety limits, execute.

Resource limits are a *host-safety floor* attached to each profile, separate from the
isolation flags that distinguish the profiles. Even ``docker-baseline`` therefore runs with
a memory cap (swap disabled), pids/cpus/nofile/fsize caps and a wall-clock timeout, so a
resource bomb cannot take down the machine running it; a genuinely naked ``docker run``
would have none of them. ``hardened`` adds tighter limits and a size-capped workspace.
"""

from __future__ import annotations

from .backends.docker import DEFAULT_IMAGE, DockerBackend
from .backends.subprocess_backend import ENFORCED_LIMITS as SUBPROCESS_ENFORCED
from .backends.subprocess_backend import SubprocessBackend
from .profiles import canonical_name, get_profile
from .types import Limits, RunResult, RunSpec

_MB = 1 << 20

PROFILE_LIMITS: dict[str, Limits] = {
    # Only wall/output (plus memory/fsize/nofile rlimits on POSIX) are enforced here; see
    # enforced_limits().
    "subprocess": Limits(wall_seconds=10.0, memory_bytes=512 * _MB, fsize_bytes=64 * _MB),
    "docker-baseline": Limits(
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
        # tmpfs pages count against the memory cgroup, so this must stay well under it.
        workspace_bytes=32 * _MB,
    ),
}

_ALL_LIMITS = (
    "wall_seconds",
    "output_bytes",
    "memory_bytes",
    "cpus",
    "pids",
    "nofile",
    "fsize_bytes",
    "workspace_bytes",
)


def limits_for(profile_name: str) -> Limits:
    return PROFILE_LIMITS[canonical_name(profile_name)]


def enforced_limits(profile_name: str) -> dict[str, object]:
    """The limits of a profile that are actually enforced on this OS, by field name."""
    prof = get_profile(profile_name)
    lim = limits_for(prof.name)
    names = SUBPROCESS_ENFORCED if prof.backend == "subprocess" else _ALL_LIMITS
    return {n: getattr(lim, n) for n in names if getattr(lim, n) is not None}


class Sandbox:
    """Entry point. Holds one backend per kind and routes by profile."""

    def __init__(self, image: str = DEFAULT_IMAGE, session: str | None = None) -> None:
        self._docker = DockerBackend(image=image, session=session)
        self._subprocess = SubprocessBackend()

    @property
    def image(self) -> str:
        return self._docker.image

    @property
    def session(self) -> str:
        """The label value on every container this Sandbox creates."""
        return self._docker.session

    def docker_available(self) -> bool:
        return self._docker.available()

    def preflight(self) -> None:
        """Pull the image if missing and check it can enforce the budget (see DockerBackend)."""
        self._docker.preflight()

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
            limits=limits or limits_for(prof.name),
        )
        return self.run_spec(spec, prof.name)

    def run_spec(self, spec: RunSpec, profile: str) -> RunResult:
        prof = get_profile(profile)
        if prof.backend == "docker":
            if not self.docker_available():
                return RunResult(
                    backend="docker",
                    profile=prof.name,
                    exit_code=None,
                    stdout="",
                    stderr="",
                    duration_s=0.0,
                    timed_out=False,
                    error="docker engine unavailable",
                )
            return self._docker.run(spec, prof)
        return self._subprocess.run(spec, prof)

    def cleanup(self, session: str | None = None) -> int:
        """Remove every container of one session (this Sandbox's by default), any state."""
        return self._docker.cleanup(session)

    def remove_stopped(self) -> int:
        """Remove stopped agent-sandbox containers of any session (never a live run)."""
        return self._docker.remove_stopped()
