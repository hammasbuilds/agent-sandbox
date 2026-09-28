"""Named hardening profiles.

A profile is a small, declarative description of the *isolation* flags a run gets.
Resource limits live separately, per profile, in ``runner.PROFILE_LIMITS``. Backends
translate a profile into their own controls; the subprocess backend ignores the
Docker-only knobs (that is the entire point of comparing them).

The three shipped profiles form a ladder:

* ``subprocess``      -- a child process on the host: no isolation at all, the unsafe
                         baseline (subprocess backend only).
* ``docker-baseline`` -- Docker's default isolation (bridge network, root in the container,
                         writable rootfs, Docker's default capabilities and seccomp), plus
                         the harness's host-safety limits: memory with swap disabled,
                         pids, cpus, nofile and fsize ulimits, and a wall-clock timeout.
* ``hardened``        -- network off, read-only rootfs, size-capped tmpfs for /tmp and for
                         the /work workspace, non-root user, ``--cap-drop ALL``,
                         ``no-new-privileges``, and tighter resource limits.

``default`` is accepted as a legacy alias for ``docker-baseline``: the profile used to be
called that, and it described it as "plain docker run", which it never was.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Profile:
    name: str
    backend: str  # "subprocess" or "docker"
    # Docker knobs (ignored by the subprocess backend):
    network: str = "bridge"  # "bridge" | "none"
    read_only_rootfs: bool = False
    tmpfs: dict[str, str] = field(default_factory=dict)  # mount point -> options
    user: str | None = None  # e.g. "65534:65534"
    cap_drop_all: bool = False
    no_new_privileges: bool = False
    seccomp: str = "default"  # "default" uses Docker's built-in profile; "unconfined" disables
    description: str = ""


SUBPROCESS = Profile(
    name="subprocess",
    backend="subprocess",
    description="Child process directly on this host. No isolation: it sees your files, "
    "environment and network. The unsafe baseline.",
)

DOCKER_BASELINE = Profile(
    name="docker-baseline",
    backend="docker",
    network="bridge",
    read_only_rootfs=False,
    user=None,
    cap_drop_all=False,
    no_new_privileges=False,
    description="Docker's default isolation (bridge network, root, writable rootfs, default "
    "caps and seccomp) plus host-safety limits: memory (no swap), pids, cpus, nofile, fsize, "
    "wall-clock timeout. /work is an uncapped host bind mount.",
)

HARDENED = Profile(
    name="hardened",
    backend="docker",
    network="none",
    read_only_rootfs=True,
    tmpfs={"/tmp": "rw,nosuid,nodev,size=16m"},
    user="65534:65534",  # nobody:nogroup
    cap_drop_all=True,
    no_new_privileges=True,
    seccomp="default",
    description="Network off, read-only rootfs, size-capped tmpfs /tmp and /work, non-root, "
    "cap-drop ALL, no-new-privileges, tight memory/pids/cpu/ulimit caps, wall-clock timeout.",
)

PROFILES: dict[str, Profile] = {p.name: p for p in (SUBPROCESS, DOCKER_BASELINE, HARDENED)}
# Legacy name kept so older callers keep working.
ALIASES: dict[str, str] = {"default": DOCKER_BASELINE.name}


def canonical_name(name: str) -> str:
    """Resolve a legacy alias to its profile name; raise on an unknown name."""
    name = ALIASES.get(name, name)
    if name not in PROFILES:
        known = ", ".join(PROFILES)
        raise ValueError(f"unknown profile {name!r}; known profiles: {known}")
    return name


def get_profile(name: str) -> Profile:
    return PROFILES[canonical_name(name)]
