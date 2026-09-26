"""Pure unit tests for the docker run argv builder -- no engine needed."""

from __future__ import annotations

from agent_sandbox.backends.docker_cmd import build_run_argv
from agent_sandbox.profiles import DEFAULT, HARDENED
from agent_sandbox.runner import limits_for


def _argv(profile, limits):
    return build_run_argv(
        image="python:3.12-slim",
        profile=profile,
        limits=limits,
        container_name="agsbx-test",
        workdir_mount="/host/work",
        inner_argv=["python", "-u", "/work/main.py"],
        env={"SBX_NONCE": "abc"},
        run_id="rid123",
    )


def test_hardened_sets_every_control():
    argv = _argv(HARDENED, limits_for("hardened"))
    s = " ".join(argv)
    assert "--network none" in s
    assert "--read-only" in s
    assert "--user 65534:65534" in s
    assert "--cap-drop ALL" in s
    assert "--security-opt no-new-privileges" in s
    assert "--tmpfs /tmp:rw,nosuid,nodev,size=16m" in s
    assert "--pids-limit 64" in s
    assert "--memory 134217728" in s
    assert "--cpus 1" in s
    assert "--ulimit nofile=256:256" in s
    assert "--label agent-sandbox=1" in s
    assert argv[-4:] == ["python:3.12-slim", "python", "-u", "/work/main.py"]


def test_default_omits_hardening_but_keeps_safety_limits():
    argv = _argv(DEFAULT, limits_for("default"))
    s = " ".join(argv)
    assert "--network bridge" in s
    assert "--read-only" not in s
    assert "--cap-drop" not in s
    assert "--user" not in s
    assert "no-new-privileges" not in s
    # host-safety floor is still present under default
    assert "--memory 536870912" in s
    assert "--pids-limit 512" in s


def test_workdir_is_always_bind_mounted():
    # /work is a writable bind mount under every docker profile, so code and files
    # in/out work even when the rootfs is read-only.
    for prof in (DEFAULT, HARDENED):
        argv = _argv(prof, limits_for(prof.name))
        assert "--volume /host/work:/work:rw" in " ".join(argv)


def test_hardened_tmpfs_is_tmp_only():
    argv = _argv(HARDENED, limits_for("hardened"))
    s = " ".join(argv)
    assert "--tmpfs /tmp:rw,nosuid,nodev,size=16m" in s
    assert "--tmpfs /work" not in s


def test_env_is_explicit_allowlist():
    argv = _argv(DEFAULT, limits_for("default"))
    assert "--env SBX_NONCE=abc" in " ".join(argv)


def test_memory_swap_pinned_to_memory():
    argv = _argv(HARDENED, limits_for("hardened"))
    # swap == memory so there is no swap headroom
    assert "--memory-swap 134217728" in " ".join(argv)
