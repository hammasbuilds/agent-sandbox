"""Pure construction of the ``docker run`` / ``docker exec`` argvs from a spec + profile.

Kept side-effect-free so the exact flags a profile produces can be asserted in unit
tests without a Docker engine present. The DockerBackend calls these and then execs them.

A run is two commands. ``docker run --detach`` starts the container with every isolation
flag and limit, idling on ``sleep``; ``docker exec`` then runs the program in it under
``timeout``. Keeping the container alive after the program exits lets the harness read
Docker's ``OOMKilled`` state and copy output files out of a tmpfs workspace before the
container is removed.
"""

from __future__ import annotations

from ..profiles import Profile
from ..types import Limits

LABEL = "agent-sandbox"
# Every container carries LABEL=1, LABEL-run=<run id> and LABEL-session=<session id>. The
# session id is unique per DockerBackend, so a backend (or a test) can find and remove the
# containers it created without touching another process's runs.
SESSION_LABEL = f"{LABEL}-session"
WORKDIR = "/work"
INPUT_DIR = "/in"  # read-only bind of the harness's input dir when /work is a tmpfs
# After the wall budget, `timeout` sends SIGTERM; a program that ignores it gets SIGKILL
# this many seconds later. Without it, a SIGTERM-ignoring program outlives its budget.
KILL_AFTER_S = 2


def fmt_seconds(v: float) -> str:
    return f"{v:.3f}".rstrip("0").rstrip(".")


def build_run_argv(
    *,
    image: str,
    profile: Profile,
    limits: Limits,
    container_name: str,
    host_workdir: str,
    keepalive_s: float,
    env: dict[str, str],
    run_id: str,
    session: str,
) -> list[str]:
    """Return the ``docker run --detach ...`` argv that creates the run's container.

    ``host_workdir`` holds the program and its input files. Without a workspace cap it is
    bind-mounted read-write at /work, so /work is limited only by the host disk. With
    ``limits.workspace_bytes`` set, /work is a tmpfs of that size and ``host_workdir`` is
    bind-mounted read-only at /in, to be copied into /work when the program starts.

    The container's main process is ``sleep keepalive_s``: if the harness itself dies, the
    container stops on its own and ``agent-sandbox cleanup`` removes it once it has stopped.
    """
    argv: list[str] = [
        "docker",
        "run",
        "--detach",
        "--name",
        container_name,
        "--label",
        f"{LABEL}=1",
        "--label",
        f"{LABEL}-run={run_id}",
        "--label",
        f"{SESSION_LABEL}={session}",
    ]

    # Networking.
    argv += ["--network", profile.network]

    # Filesystem. A read-only rootfs protects /, /etc, /usr and everything else; the
    # profile's tmpfs mounts (e.g. /tmp) are size-capped; /work is either a size-capped
    # tmpfs or an uncapped host bind mount (see docstring).
    if profile.read_only_rootfs:
        argv += ["--read-only"]
    for mount, opts in profile.tmpfs.items():
        argv += ["--tmpfs", f"{mount}:{opts}"]
    if limits.workspace_bytes is not None:
        opts = f"rw,nosuid,nodev,size={limits.workspace_bytes}"
        if profile.user is not None:
            uid, _, gid = profile.user.partition(":")
            opts += f",uid={uid},gid={gid or uid},mode=0700"
        argv += ["--tmpfs", f"{WORKDIR}:{opts}"]
        argv += ["--volume", f"{host_workdir}:{INPUT_DIR}:ro"]
    else:
        argv += ["--volume", f"{host_workdir}:{WORKDIR}:rw"]
    argv += ["--workdir", WORKDIR]

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
        argv += ["--ulimit", f"fsize={limits.fsize_bytes}:{limits.fsize_bytes}"]  # bytes

    # Environment (explicit allow-list only; nothing from the host leaks in).
    for key, value in env.items():
        argv += ["--env", f"{key}={value}"]

    argv += [image, "sleep", fmt_seconds(keepalive_s)]
    return argv


def build_exec_argv(
    *,
    container_name: str,
    payload: list[str],
    wall_seconds: float,
    copy_inputs: bool,
) -> list[str]:
    """Return the ``docker exec`` argv that runs ``payload`` under the wall-clock budget.

    The budget is enforced inside the container by coreutils ``timeout`` (so Docker's
    start-up time never eats into it): SIGTERM at the budget, SIGKILL ``KILL_AFTER_S``
    later. With ``copy_inputs`` the inputs are first copied from /in into the tmpfs /work;
    the copy runs before ``timeout`` starts, so it does not count against the budget.
    """
    timed = ["timeout", "-k", str(KILL_AFTER_S), fmt_seconds(wall_seconds), *payload]
    if copy_inputs:
        timed = ["sh", "-c", f'cp -R {INPUT_DIR}/. {WORKDIR}/ && exec "$@"', "sh", *timed]
    return ["docker", "exec", "--interactive", "--workdir", WORKDIR, container_name, *timed]


def _fmt_cpus(cpus: float) -> str:
    text = f"{cpus:.3f}".rstrip("0").rstrip(".")
    return text or "0"
