from __future__ import annotations

from agent_sandbox.attacks.registry import build_attacks
from agent_sandbox.runner import Sandbox
from agent_sandbox.types import RunResult


def test_suite_has_30_plus_unique_attacks():
    attacks = build_attacks()
    assert len(attacks) >= 30
    names = [a.name for a in attacks]
    assert len(names) == len(set(names))


def test_every_attack_is_well_formed():
    for a in build_attacks():
        assert a.code.strip()
        assert callable(a.check)
        assert a.goal and a.mechanism and a.category


def test_categories_span_the_threat_model():
    cats = {a.category for a in build_attacks()}
    for expected in ("network", "data", "privilege", "infoleak", "resource", "process"):
        assert expected in cats


def test_docker_profile_returns_error_when_engine_missing(monkeypatch):
    sandbox = Sandbox()
    monkeypatch.setattr(sandbox._docker, "available", lambda: False)
    r = sandbox.run(code="print(1)", profile="hardened")
    assert isinstance(r, RunResult)
    assert r.error == "docker engine unavailable"
    assert r.exit_code is None


def test_subprocess_profile_runs_without_docker():
    sandbox = Sandbox()
    r = sandbox.run(code="print(2 + 2)", profile="subprocess")
    assert r.stdout.strip() == "4"
    assert r.ok
