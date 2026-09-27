"""Pure construction of the ``docker run`` argv from a spec + profile.

Kept side-effect-free so the exact flags a profile produces can be asserted in unit
tests without a Docker engine present. The DockerBackend calls this and then execs it.
"""

from __future__ import annotations

from ..profiles import Profile
from ..types import Limits

LABEL = "agent-sandbox"


def build_run_argv(
    *,
    image: str,
    profile: Profile,
    limits: Limits,
    container_name: str,
    workdir_mount: str | None,
    inner_argv: list[str],
    env: dict[str, str],
    run_id: str,
) -> list[str]:
    """Return the full ``docker run ...`` argv for one execution.

    ``workdir_mount`` is a host path bind-mounted read-write at ``/work`` when the
    rootfs is writable; when the profile uses a read-only rootfs the working directory
    is a tmpfs instead and files are streamed in via the caller, so no bind is used.
    """
    argv: list[str] = [
        "docker",
        "run",
        "--rm",
        "--interactive",  # keep stdin open so piped input reaches the code
        "--name",
        container_name,
        "--label",
        f"{LABEL}=1",
        "--label",
        f"{LABEL}-run={run_id}",
    ]

    # Networking.
    argv += ["--network", profile.network]

    # Filesystem. A read-only rootfs protects /, /etc, /usr and everything else; the
    # working directory is always a writable bind mount at /work (a bind overrides the
    # read-only rootfs), which is where code and files-in/out live, and /tmp is a
    # size-capped tmpfs. Nothing else in the container is writable under `hardened`.
    if profile.read_only_rootfs:
        argv += ["--read-only"]
    for mount, opts in profile.tmpfs.items():
        argv += ["--tmpfs", f"{mount}:{opts}"]
    if workdir_mount is not None:
        argv += ["--volume", f"{workdir_mount}:/work:rw"]
    argv += ["--workdir", "/work"]

    # Identity / privileges.
    if profile.user is not None:
        argv += ["--user", profile.user]
    if profile.cap_drop_all:
        argv += ["--cap-drop", "ALL"]
    if profile.no_new_privileges:
        argv += ["--security-opt", "no-new-privileges"]
    if profile.seccomp == "unconfined":
        argv += ["--security-opt", "seccomp=unconfined"]
    # seccomp == "default" -> Docker applies its built-in profile with no flag.

    # Resource limits (cgroup-backed).
    if limits.memory_bytes is not None:
        argv += ["--memory", str(limits.memory_bytes)]
        argv += ["--memory-swap", str(limits.memory_bytes)]  # disable swap headroom
    if limits.cpus is not None:
        argv += ["--cpus", _fmt_cpus(limits.cpus)]
    if limits.pids is not None:
        argv += ["--pids-limit", str(limits.pids)]
    if limits.nofile is not None:
        argv += ["--ulimit", f"nofile={limits.nofile}:{limits.nofile}"]
    if limits.fsize_bytes is not None:
        blocks = limits.fsize_bytes  # docker ulimit fsize is in bytes
        argv += ["--ulimit", f"fsize={blocks}:{blocks}"]

    # Environment (explicit allow-list only; nothing from the host leaks in).
    for key, value in env.items():
        argv += ["--env", f"{key}={value}"]

    argv += [image, *inner_argv]
    return argv


def _fmt_cpus(cpus: float) -> str:
    text = f"{cpus:.3f}".rstrip("0").rstrip(".")
    return text or "0"
