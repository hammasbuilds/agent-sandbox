from __future__ import annotations

import os

import pytest

from agent_sandbox import cli
from agent_sandbox.profiles import PROFILES, get_profile
from agent_sandbox.runner import Sandbox, enforced_limits, limits_for
from agent_sandbox.types import Limits, RunResult, RunSpec


def test_runspec_requires_exactly_one_source():
    with pytest.raises(ValueError):
        RunSpec()  # neither
    with pytest.raises(ValueError):
        RunSpec(code="x", argv=("python",))  # both
    assert RunSpec(code="print(1)").code == "print(1)"
    assert RunSpec(argv=("echo", "hi")).argv == ("echo", "hi")


@pytest.mark.parametrize("rel", ["../escape.txt", "/etc/passwd", "a/../../b", "C:\\x", ""])
def test_runspec_rejects_paths_outside_workdir(rel):
    with pytest.raises(ValueError):
        RunSpec(code="print(1)", files_in={rel: b"x"})
    with pytest.raises(ValueError):
        RunSpec(code="print(1)", files_out=(rel,))


def test_runspec_accepts_nested_relative_paths():
    s = RunSpec(code="print(1)", files_in={"data/in.txt": b"x"}, files_out=("out/r.txt",))
    assert "data/in.txt" in s.files_in


def test_cli_file_in_roundtrip(tmp_path, capsys):
    from agent_sandbox.cli import main

    src = tmp_path / "numbers.txt"
    src.write_text("4 5 6")
    code = "print(sum(map(int, open('nums.txt').read().split())))"
    rc = main(["run", "--profile", "subprocess", "--file-in", f"{src}:nums.txt", "--code", code])
    assert rc == 0
    assert capsys.readouterr().out.strip().splitlines()[0] == "15"


def test_limits_with_is_immutable_copy():
    a = Limits(wall_seconds=5)
    b = a.with_(wall_seconds=9)
    assert a.wall_seconds == 5
    assert b.wall_seconds == 9


@pytest.mark.parametrize(
    "bad",
    [
        {"wall_seconds": 0},  # `timeout 0` would mean NO timeout
        {"wall_seconds": -1},
        {"memory_bytes": 0},
        {"pids": -5},
        {"cpus": 0.0},
        {"output_bytes": 0},
    ],
)
def test_limits_reject_non_positive(bad):
    with pytest.raises(ValueError):
        Limits(**bad)


def test_cli_rejects_zero_timeout():
    from agent_sandbox.cli import main

    with pytest.raises(SystemExit) as e:
        main(["run", "--profile", "subprocess", "--timeout", "0", "--code", "print(1)"])
    assert "bad --timeout" in str(e.value)


def test_cli_rejects_missing_file_and_bad_env():
    from agent_sandbox.cli import main

    with pytest.raises(SystemExit) as e:
        main(["run", "--profile", "subprocess", "--file", "definitely_missing.py"])
    assert "no such file" in str(e.value)
    with pytest.raises(SystemExit) as e:
        main(["run", "--profile", "subprocess", "--env", "NOEQUALS", "--code", "print(1)"])
    assert "KEY=VALUE" in str(e.value)


def test_runresult_ok_and_summary():
    ok = RunResult("docker", "hardened", 0, "hi", "", 0.4, False)
    assert ok.ok
    assert "0.40s" in ok.summary()
    bad = RunResult("docker", "hardened", None, "", "", 10.0, True)
    assert not bad.ok
    assert "TIMED_OUT" in bad.summary()


def test_get_profile_unknown_raises():
    with pytest.raises(ValueError):
        get_profile("nope")


def test_profiles_and_limits_cover_each_other():
    assert set(PROFILES) == {"subprocess", "docker-baseline", "hardened"}
    for name in PROFILES:
        assert limits_for(name).wall_seconds > 0


def test_legacy_default_name_is_an_alias():
    assert get_profile("default") is get_profile("docker-baseline")
    assert limits_for("default") is limits_for("docker-baseline")


def test_no_profile_claims_to_be_plain_docker_run():
    for prof in PROFILES.values():
        assert "plain" not in prof.description.lower()
        assert "nothing added" not in prof.description.lower()


def test_hardened_is_tighter_than_baseline():
    d, h = limits_for("docker-baseline"), limits_for("hardened")
    assert h.memory_bytes < d.memory_bytes
    assert h.pids < d.pids
    assert d.workspace_bytes is None  # baseline: uncapped bind mount
    assert h.workspace_bytes is not None and h.workspace_bytes < h.memory_bytes


def test_enforced_limits_are_honest_about_the_subprocess_backend():
    sub = enforced_limits("subprocess")
    assert "wall_seconds" in sub and "output_bytes" in sub
    assert "pids" not in sub and "cpus" not in sub and "workspace_bytes" not in sub
    if os.name == "nt":
        assert "memory_bytes" not in sub and "fsize_bytes" not in sub
    hard = enforced_limits("hardened")
    assert {"memory_bytes", "pids", "cpus", "workspace_bytes"} <= set(hard)


def test_cli_file_out_escape_is_a_clean_error():
    with pytest.raises(SystemExit) as e:
        cli.main(["run", "--profile", "subprocess", "--file-out", "../x", "--code", "print(1)"])
    assert "--file-out" in str(e.value) and "inside the workdir" in str(e.value)


@pytest.mark.parametrize("bad", ["0", "-3", "two"])
def test_cli_latency_rounds_must_be_positive(bad, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["latency", "--rounds", bad, "--out", "x.json"])
    assert e.value.code == 2  # argparse usage error, not a traceback
    assert "--rounds" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [["latency", "--out", "x.json"], ["cleanup"], ["chaos", "--out", "x.json"]],
)
def test_cli_docker_commands_fail_loudly_without_docker(argv, monkeypatch):
    monkeypatch.setattr(Sandbox, "docker_available", lambda self: False)
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    assert "needs a running Docker engine" in str(e.value)


def test_cli_run_reports_docker_down_with_nonzero_exit(monkeypatch, capsys):
    monkeypatch.setattr(Sandbox, "docker_available", lambda self: False)
    rc = cli.main(["run", "--profile", "hardened", "--code", "print(1)"])
    assert rc == 3
    assert "docker engine unavailable" in capsys.readouterr().err


def test_cli_refuses_to_overwrite_default_results(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "results").mkdir()
    (tmp_path / "results" / "latency.json").write_text("{}")
    monkeypatch.setattr(Sandbox, "docker_available", lambda self: True)
    with pytest.raises(SystemExit) as e:
        cli.main(["latency", "--rounds", "1"])
    assert "--force" in str(e.value)
    assert (tmp_path / "results" / "latency.json").read_text() == "{}"


def test_cli_subprocess_profile_warns(capsys):
    rc = cli.main(["run", "--profile", "subprocess", "--code", "print(1)"])
    assert rc == 0
    assert "runs the code directly on this host" in capsys.readouterr().err


def test_cli_profiles_lists_only_enforced_limits(capsys):
    assert cli.main(["profiles"]) == 0
    out = capsys.readouterr().out
    sub_block = out.split("docker-baseline")[0]
    assert "pids=" not in sub_block and "cpus=" not in sub_block
    if os.name == "nt":
        assert "memory=" not in sub_block
    assert "plain" not in out.lower()
    assert "workspace=32m" in out


@pytest.mark.parametrize("bad", [float("inf"), float("nan"), 3601.0])
def test_limits_reject_unbounded_wall_clock(bad):
    with pytest.raises(ValueError, match="finite"):
        Limits(wall_seconds=bad)


@pytest.mark.parametrize("bad", ["inf", "nan", "1e9"])
def test_cli_rejects_infinite_timeout(bad):
    with pytest.raises(SystemExit) as e:
        cli.main(["run", "--profile", "subprocess", "--timeout", bad, "--code", "print(1)"])
    assert "bad --timeout" in str(e.value)


@pytest.mark.parametrize("rel", [".", "./a", "a//b", "a/", "a/./b"])
def test_runspec_rejects_non_normal_paths(rel):
    with pytest.raises(ValueError):
        RunSpec(code="print(1)", files_in={rel: b"x"})


def test_runspec_rejects_file_and_directory_clash_and_program_overwrite():
    with pytest.raises(ValueError, match="directory"):
        RunSpec(code="print(1)", files_in={"a": b"1", "a/b": b"2"})
    with pytest.raises(ValueError, match="overwritten"):
        RunSpec(code="print(1)", files_in={"main.py": b"x"})
    # With an argv there is no program file, so main.py is an ordinary input.
    assert "main.py" in RunSpec(argv=("python", "main.py"), files_in={"main.py": b"x"}).files_in


def _local(tmp_path, name="f.txt"):
    p = tmp_path / name
    p.write_text("data")
    return p


@pytest.mark.parametrize(
    ("dests", "message"),
    [
        (["."], "normal form"),
        (["a", "a/b"], "needs it to be a directory"),
        (["main.py"], "overwritten by the program"),
        (["x.txt", "x.txt"], "same destination"),
    ],
)
def test_cli_file_in_bad_destinations_are_clean_errors(tmp_path, dests, message):
    src = _local(tmp_path)
    argv = ["run", "--profile", "subprocess", "--code", "print(1)"]
    for d in dests:
        argv += ["--file-in", f"{src}:{d}"]
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    assert str(e.value).startswith("agent-sandbox: error: --file-in")
    assert message in str(e.value)


def test_cli_file_in_named_main_py_is_refused_without_rename(tmp_path):
    src = _local(tmp_path, "main.py")
    with pytest.raises(SystemExit) as e:
        cli.main(["run", "--profile", "subprocess", "--file-in", str(src), "--code", "print(1)"])
    assert "main.py" in str(e.value)


def test_cli_chaos_subprocess_only_does_not_need_docker(tmp_path, monkeypatch, capsys):
    from agent_sandbox import chaos
    from agent_sandbox.attacks.registry import build_attacks

    monkeypatch.setattr(Sandbox, "docker_available", lambda self: False)
    only = [a for a in build_attacks() if a.name == "env_secret_read"]
    monkeypatch.setattr(chaos, "build_attacks", lambda: only)
    out = tmp_path / "c.json"
    rc = cli.main(["chaos", "--profiles", "subprocess", "--reps", "1", "--out", str(out)])
    assert rc == 0
    import json

    report = json.loads(out.read_text())
    assert report["summary"]["matrix"] == {"env_secret_read": {"subprocess": "succeeded"}}
    assert "breached 1/1" in capsys.readouterr().out


def test_cli_chaos_docker_profile_names_what_needs_docker(monkeypatch):
    monkeypatch.setattr(Sandbox, "docker_available", lambda self: False)
    with pytest.raises(SystemExit) as e:
        cli.main(["chaos", "--profiles", "subprocess", "docker-baseline", "--out", "x.json"])
    assert "docker-baseline" in str(e.value) and "Docker engine" in str(e.value)


def test_cli_cleanup_removes_only_stopped_containers_by_default(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(Sandbox, "docker_available", lambda self: True)
    monkeypatch.setattr(Sandbox, "remove_stopped", lambda self: calls.append("stopped") or 2)
    monkeypatch.setattr(Sandbox, "cleanup", lambda self, s=None: calls.append(s) or 1)
    assert cli.main(["cleanup"]) == 0
    assert cli.main(["cleanup", "--session", "abc"]) == 0
    assert calls == ["stopped", "abc"]
    out = capsys.readouterr().out
    assert "removed 2 stopped" in out and "session abc" in out
