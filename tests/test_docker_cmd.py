"""Pure unit tests for the docker run/exec argv builders -- no engine needed."""

from __future__ import annotations

from agent_sandbox.backends.docker_cmd import KILL_AFTER_S, build_exec_argv, build_run_argv
from agent_sandbox.profiles import DOCKER_BASELINE, HARDENED
from agent_sandbox.runner import limits_for


def _argv(profile, limits):
    return build_run_argv(
        image="python:3.12-slim",
        profile=profile,
        limits=limits,
        container_name="agsbx-test",
        host_workdir="/host/work",
        keepalive_s=100,
        env={"SBX_NONCE": "abc"},
        run_id="rid123",
        session="sess42",
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
    assert "--label agent-sandbox-run=rid123" in s
    assert "--label agent-sandbox-session=sess42" in s  # what cleanup and tests filter on
    assert argv[-3:] == ["python:3.12-slim", "sleep", "100"]


def test_container_is_detached_and_named():
    argv = _argv(HARDENED, limits_for("hardened"))
    assert argv[:3] == ["docker", "run", "--detach"]
    assert "--rm" not in argv  # kept after exit so OOMKilled can be read, then removed
    assert argv[argv.index("--name") + 1] == "agsbx-test"


def test_baseline_omits_hardening_but_keeps_safety_limits():
    argv = _argv(DOCKER_BASELINE, limits_for("docker-baseline"))
    s = " ".join(argv)
    assert "--network bridge" in s
    assert "--read-only" not in s
    assert "--cap-drop" not in s
    assert "--user" not in s
    assert "no-new-privileges" not in s
    # host-safety floor is present under the baseline
    assert "--memory 536870912" in s
    assert "--memory-swap 536870912" in s
    assert "--pids-limit 512" in s
    assert "--cpus 2" in s
    assert "--ulimit fsize=67108864:67108864" in s


def test_baseline_workdir_is_an_uncapped_bind_mount():
    s = " ".join(_argv(DOCKER_BASELINE, limits_for("docker-baseline")))
    assert "--volume /host/work:/work:rw" in s
    assert "--tmpfs /work" not in s


def test_hardened_workdir_is_a_size_capped_tmpfs_with_readonly_inputs():
    s = " ".join(_argv(HARDENED, limits_for("hardened")))
    size = limits_for("hardened").workspace_bytes
    assert f"--tmpfs /work:rw,nosuid,nodev,size={size},uid=65534,gid=65534,mode=0700" in s
    assert "--volume /host/work:/in:ro" in s
    assert "/host/work:/work" not in s  # the host dir is never writable from inside


def test_workspace_cap_is_driven_by_limits_not_profile():
    lim = limits_for("docker-baseline").with_(workspace_bytes=1 << 20)
    s = " ".join(_argv(DOCKER_BASELINE, lim))
    assert "--tmpfs /work:rw,nosuid,nodev,size=1048576" in s
    assert "uid=" not in s  # no --user, so no ownership options


def test_env_is_explicit_allowlist():
    argv = _argv(DOCKER_BASELINE, limits_for("docker-baseline"))
    assert "--env SBX_NONCE=abc" in " ".join(argv)


def test_exec_runs_timeout_with_kill_after():
    argv = build_exec_argv(
        container_name="agsbx-test", payload=["python", "-u", "/work/main.py"],
        wall_seconds=3.0, copy_inputs=False,
    )  # fmt: skip
    assert argv[:6] == ["docker", "exec", "--interactive", "--workdir", "/work", "agsbx-test"]
    assert argv[6:] == ["timeout", "-k", str(KILL_AFTER_S), "3", "python", "-u", "/work/main.py"]


def test_exec_copies_inputs_before_starting_the_clock():
    argv = build_exec_argv(
        container_name="c", payload=["python", "main.py"], wall_seconds=2.5, copy_inputs=True
    )
    i = argv.index("sh")
    assert argv[i : i + 2] == ["sh", "-c"]
    assert argv[i + 2].startswith("cp -R /in/. /work/ && exec")
    assert argv[-6:] == ["timeout", "-k", str(KILL_AFTER_S), "2.5", "python", "main.py"]


class _Recorder:
    def __init__(self, stdout: str = "") -> None:
        self.argvs: list[list[str]] = []
        self.stdout = stdout

    def __call__(self, argv, **kw):
        import subprocess

        self.argvs.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, self.stdout, "")


def test_backend_cleanup_filters_on_its_own_session(monkeypatch):
    from agent_sandbox.backends import docker as docker_mod

    rec = _Recorder("id1\nid2\n")
    monkeypatch.setattr(docker_mod.subprocess, "run", rec)
    backend = docker_mod.DockerBackend(session="mine")
    assert backend.cleanup() == 2
    listing, removal = rec.argvs
    assert "label=agent-sandbox-session=mine" in listing
    assert "label=agent-sandbox=1" not in listing  # never every labelled container
    assert removal == ["docker", "rm", "-f", "id1", "id2"]


def test_backend_remove_stopped_never_lists_running_containers(monkeypatch):
    from agent_sandbox.backends import docker as docker_mod

    rec = _Recorder("")
    monkeypatch.setattr(docker_mod.subprocess, "run", rec)
    assert docker_mod.DockerBackend().remove_stopped() == 0
    (listing,) = rec.argvs
    assert "status=exited" in listing and "status=dead" in listing
    assert "status=running" not in listing


def test_each_backend_gets_its_own_session():
    from agent_sandbox.backends.docker import DockerBackend

    assert DockerBackend().session != DockerBackend().session
