"""Named hardening profiles.

A profile is a small, declarative description of how much the sandbox clamps down.
Backends translate a profile into their own controls; the subprocess backend ignores
the Docker-only knobs (that is the entire point of comparing them).

The three shipped profiles form a ladder:

* ``subprocess`` -- no isolation at all, the unsafe baseline (subprocess backend only).
* ``default``    -- plain ``docker run`` with nothing added. Tests the folk claim that
                    "Docker by itself is a sandbox".
* ``hardened``   -- network off, read-only rootfs + small tmpfs, non-root user,
                    ``--cap-drop ALL``, ``--security-opt no-new-privileges``, and
                    pids/memory/cpu/ulimit caps.
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
    description="Bare child process on the host. No isolation. The unsafe baseline.",
)

DEFAULT = Profile(
    name="default",
    backend="docker",
    network="bridge",
    read_only_rootfs=False,
    user=None,
    cap_drop_all=False,
    no_new_privileges=False,
    description="Plain `docker run`, nothing added. Tests 'Docker is a sandbox by itself'.",
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
    description="Network off, read-only rootfs + tmpfs, non-root, cap-drop ALL, "
    "no-new-privileges, pids/mem/cpu/ulimit caps.",
)

PROFILES: dict[str, Profile] = {p.name: p for p in (SUBPROCESS, DEFAULT, HARDENED)}


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        known = ", ".join(PROFILES)
        raise ValueError(f"unknown profile {name!r}; known profiles: {known}") from None
