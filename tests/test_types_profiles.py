from __future__ import annotations

import pytest

from agent_sandbox.profiles import PROFILES, get_profile
from agent_sandbox.runner import limits_for
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
    assert set(PROFILES) == {"subprocess", "default", "hardened"}
    for name in PROFILES:
        assert limits_for(name).wall_seconds > 0


def test_hardened_is_tighter_than_default():
    d, h = limits_for("default"), limits_for("hardened")
    assert h.memory_bytes < d.memory_bytes
    assert h.pids < d.pids
