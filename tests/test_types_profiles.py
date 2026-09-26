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


def test_limits_with_is_immutable_copy():
    a = Limits(wall_seconds=5)
    b = a.with_(wall_seconds=9)
    assert a.wall_seconds == 5
    assert b.wall_seconds == 9


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
