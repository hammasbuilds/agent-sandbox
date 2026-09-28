"""Chaos runner: verdicts, per-rep evidence, orphan scoring, summary and report, with fakes."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from agent_sandbox import chaos
from agent_sandbox.attacks.harness import BLOCKED, ERROR, MIXED, NA, SUCCEEDED, ChaosContext
from agent_sandbox.attacks.registry import build_attacks
from agent_sandbox.chaos import (
    Cell,
    ChaosRunner,
    _container_name,
    _docker_orphan_check,
    _subprocess_orphan_verdict,
    _verdict,
    build_report,
    canary_candidates,
    link_target,
    summarise,
)
from agent_sandbox.types import RunResult, RunSpec

ATTACKS = {a.name: a for a in build_attacks()}


class FakeSandbox:
    """Stands in for Sandbox: returns canned results and records what it was asked."""

    image = "fake:img"
    session = "sess123"

    def __init__(self, results=None, docker: bool = True) -> None:
        self.results = list(results or [])
        self.calls: list[tuple[RunSpec, str]] = []
        self.docker = docker

    def docker_available(self) -> bool:
        return self.docker

    def run_spec(self, spec: RunSpec, profile: str) -> RunResult:
        self.calls.append((spec, profile))
        if self.results:
            return self.results.pop(0)
        return RunResult("docker", profile, 0, "UID 0\n", "", 0.5, False)


def _res(stdout="", **kw) -> RunResult:
    base = dict(
        backend="docker",
        profile="docker-baseline",
        exit_code=0,
        stdout=stdout,
        stderr="",
        duration_s=0.2,
        timed_out=False,
    )
    base.update(kw)
    return RunResult(**base)


def _cell(attack: str, profile: str, verdict: str) -> Cell:
    return Cell(attack, "cat", profile, "g", "m", "payload", 1, 0, 0, 0, 0, verdict, "ev", 0.1)


# -- verdicts --------------------------------------------------------------------------


def _c(s=0, b=0, n=0, e=0):
    return {SUCCEEDED: s, BLOCKED: b, NA: n, ERROR: e}


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        (_c(b=3), BLOCKED),
        (_c(s=3), SUCCEEDED),
        (_c(n=3), NA),
        (_c(e=3), ERROR),
        (_c(n=1, b=2), BLOCKED),  # n/a reps are set aside, the rest agree
        (_c(n=2, s=1), SUCCEEDED),
        (_c(n=1, e=2), ERROR),  # was scored "blocked" with no blocked rep at all
        (_c(b=2, e=1), ERROR),  # incomplete evidence is not a block
        (_c(s=1, b=2), MIXED),  # a breach is never hidden, nor overstated
        (_c(s=1, e=2), MIXED),
        (_c(s=1, b=1, e=1), MIXED),
    ],
)
def test_verdict_needs_every_scored_rep_to_agree(counts, expected):
    assert _verdict(counts) == expected


# -- run_cell / run_all ----------------------------------------------------------------


def test_run_cell_canonicalises_legacy_profile_name():
    runner = ChaosRunner(FakeSandbox(), reps=2)
    try:
        cell = runner.run_cell(ATTACKS["run_as_root"], "default")
    finally:
        runner.close()
    assert cell.profile == "docker-baseline"
    assert cell.verdict == SUCCEEDED
    summarise([cell])  # used to raise KeyError for any name outside the old PROFILE_ORDER


def test_run_cell_surfaces_every_rep_including_errors():
    results = [
        _res("UID 0"),
        _res(error="container stopped during the run"),
        _res("UID 0"),
    ]
    runner = ChaosRunner(FakeSandbox(results), reps=3)
    try:
        cell = runner.run_cell(ATTACKS["run_as_root"], "docker-baseline")
    finally:
        runner.close()
    assert (cell.succeeded, cell.error) == (2, 1)
    assert cell.verdict == MIXED
    assert [r["status"] for r in cell.per_rep] == [SUCCEEDED, ERROR, SUCCEEDED]
    assert "container stopped" in cell.per_rep[1]["evidence"]
    assert cell.as_dict()["per_rep"][1]["status"] == ERROR


def test_linux_only_attack_is_not_run_by_subprocess_off_linux(monkeypatch):
    monkeypatch.setattr(chaos.sys, "platform", "win32")
    fake = FakeSandbox()
    runner = ChaosRunner(fake, reps=1)
    try:
        cell = runner.run_cell(ATTACKS["run_as_root"], "subprocess")
    finally:
        runner.close()
    assert cell.verdict == NA
    assert fake.calls == []


def test_run_all_refuses_docker_profiles_without_docker():
    runner = ChaosRunner(FakeSandbox(docker=False), reps=1)
    try:
        with pytest.raises(RuntimeError, match="Docker"):
            runner.run_all(("hardened",))
    finally:
        runner.close()


def test_orphan_attacks_ask_docker_to_count_lingering_processes(monkeypatch):
    monkeypatch.setattr(chaos, "_container_exists", lambda name: False)
    fake = FakeSandbox([_res("ORPHAN_PID 7", argv=("docker", "--name", "c1"))])
    runner = ChaosRunner(fake, reps=1)
    try:
        runner.run_cell(ATTACKS["orphan_survivor"], "hardened")
    finally:
        runner.close()
    spec, _ = fake.calls[0]
    assert spec.count_lingering
    assert spec.env["SBX_ORPHAN_MARKER"] == chaos.CONTAINER_ORPHAN_MARKER


def test_runner_removes_only_its_own_scratch(tmp_path):
    with ChaosRunner(FakeSandbox(), reps=1) as owned:
        mine = owned.scratch
        assert mine.is_dir()
    assert not mine.exists()

    given = tmp_path / "keep"
    ChaosRunner(FakeSandbox(), reps=1, scratch=given).close()
    assert given.is_dir()  # a caller-provided directory is never deleted


# -- orphan / time bomb scoring --------------------------------------------------------


def test_container_name_extracted_from_argv():
    argv = ("docker", "run", "--detach", "--name", "agsbx-abc123", "img", "sleep")
    assert _container_name(argv) == "agsbx-abc123"
    assert _container_name(("docker", "run")) is None


@pytest.mark.parametrize(
    ("stdout", "lingering", "exists", "expected"),
    [
        ("ORPHAN_PID 12", 1, False, BLOCKED),  # alive at exit, gone after teardown
        ("ORPHAN_PID 12", 1, True, SUCCEEDED),  # teardown failed: container survived
        ("ORPHAN_PID 12", 0, False, ERROR),  # child already dead: teardown never tested
        ("ORPHAN_PID 12", None, False, ERROR),  # count unavailable
        ("ORPHAN_PID 12", 1, None, ERROR),  # existence unknown
        ("Traceback ...", 1, False, ERROR),  # payload never spawned the child
    ],
)
def test_docker_orphan_check(stdout, lingering, exists, expected):
    r = _res(stdout, lingering_processes=lingering)
    assert _docker_orphan_check(r, exists).status == expected


def test_docker_orphan_check_is_not_vacuous_after_teardown():
    # The old check only asked "is the container gone after rm --force?", which is always
    # yes. Without a live child observed before teardown it must not score a block.
    assert _docker_orphan_check(_res("ORPHAN_PID 3", lingering_processes=0), False).status == ERROR


def test_subprocess_orphan_verdict():
    assert _subprocess_orphan_verdict(2, spawned=True).status == SUCCEEDED
    assert _subprocess_orphan_verdict(1, spawned=True).status == BLOCKED
    assert _subprocess_orphan_verdict(0, spawned=False).status == ERROR


def _ctx(backend: str) -> ChaosContext:
    return ChaosContext(nonce="n", secret="s", canary_token="t", backend=backend)


def test_resolve_orphan_subprocess_sees_a_live_marker(tmp_path, monkeypatch):
    monkeypatch.setattr(chaos, "ORPHAN_WATCH_S", 3.0)
    monkeypatch.setattr(chaos, "_kill_pid", lambda pid: None)
    marker = tmp_path / "orphan.txt"
    stop = threading.Event()

    def child():  # stands in for the detached child: keeps rewriting the marker
        i = 0
        while not stop.is_set():
            marker.write_text(str(i))
            i += 1
            time.sleep(0.1)

    t = threading.Thread(target=child, daemon=True)
    t.start()
    runner = ChaosRunner(FakeSandbox(), reps=1, scratch=tmp_path / "s")
    try:
        out = runner._resolve_orphan(
            ATTACKS["orphan_survivor"],
            _ctx("subprocess"),
            {"SBX_ORPHAN_MARKER": str(marker)},
            _res("ORPHAN_PID 42", backend="subprocess"),
        )
    finally:
        stop.set()
        t.join()
        runner.close()
    assert out.status == SUCCEEDED


def test_resolve_orphan_subprocess_dead_marker_is_blocked(tmp_path, monkeypatch):
    monkeypatch.setattr(chaos, "ORPHAN_WATCH_S", 1.0)
    monkeypatch.setattr(chaos, "_kill_pid", lambda pid: None)
    marker = tmp_path / "orphan.txt"
    marker.write_text("5")  # written once, never again
    runner = ChaosRunner(FakeSandbox(), reps=1, scratch=tmp_path / "s")
    try:
        out = runner._resolve_orphan(
            ATTACKS["orphan_survivor"],
            _ctx("subprocess"),
            {"SBX_ORPHAN_MARKER": str(marker)},
            _res("ORPHAN_PID 42", backend="subprocess"),
        )
    finally:
        runner.close()
    assert out.status == BLOCKED


def test_resolve_time_bomb_needs_the_timeout_to_have_fired(tmp_path):
    runner = ChaosRunner(FakeSandbox(), reps=1, scratch=tmp_path / "s")
    try:
        out = runner._resolve_orphan(
            ATTACKS["time_bomb"], _ctx("docker"), {}, _res("ORPHAN_PID 1", timed_out=False)
        )
    finally:
        runner.close()
    assert out.status == ERROR


def test_resolve_orphan_docker_uses_count_and_existence(tmp_path, monkeypatch):
    seen: list[str] = []
    monkeypatch.setattr(chaos, "_container_exists", lambda name: seen.append(name) or False)
    runner = ChaosRunner(FakeSandbox(), reps=1, scratch=tmp_path / "s")
    try:
        r = _res("ORPHAN_PID 9", argv=("docker", "run", "--name", "agsbx-x", "img"))
        r.lingering_processes = 1
        r.timed_out = True
        out = runner._resolve_orphan(ATTACKS["time_bomb"], _ctx("docker"), {}, r)
    finally:
        runner.close()
    assert seen == ["agsbx-x"]
    assert out.status == BLOCKED
    assert "teardown" in out.evidence


# -- canary and symlink wiring ---------------------------------------------------------


def test_canary_candidates_are_linux_paths_for_containers():
    host = r"C:\Users\me\AppData\Local\Temp\agsbx-chaos-1\canary-x.txt"
    sub = canary_candidates(host, "subprocess")
    assert sub == [host]
    dock = canary_candidates(host, "docker")
    assert "/run/desktop/mnt/host/c/Users/me/AppData/Local/Temp/agsbx-chaos-1/canary-x.txt" in dock
    assert all("\\" not in p for p in dock[1:])
    assert canary_candidates("/tmp/agsbx/canary", "docker") == ["/tmp/agsbx/canary"]


def test_link_target_depends_on_where_file_out_is_read(tmp_path):
    import tempfile

    canary = Path(tempfile.gettempdir()) / "agsbx-chaos-z" / "canary.txt"
    assert link_target("subprocess", canary) == "../agsbx-chaos-z/canary.txt"
    assert link_target("docker-baseline", canary) == "../agsbx-chaos-z/canary.txt"
    # hardened reads file-out inside the container, where a host path means nothing
    assert link_target("hardened", canary) == chaos.IN_CONTAINER_LINK_TARGET


# -- summary / report ------------------------------------------------------------------


def test_summarise_counts_every_verdict_per_profile():
    cells = [
        _cell("a", "docker-baseline", SUCCEEDED),
        _cell("b", "docker-baseline", MIXED),
        _cell("c", "docker-baseline", BLOCKED),
        _cell("d", "docker-baseline", ERROR),
        _cell("a", "hardened", BLOCKED),
        _cell("b", "hardened", NA),
    ]
    s = summarise(cells)
    assert s["matrix"]["a"] == {"docker-baseline": SUCCEEDED, "hardened": BLOCKED}
    assert s["breached"] == {"docker-baseline": 1, "hardened": 0}
    assert s["breached_any_rep"] == {"docker-baseline": 2, "hardened": 0}
    assert s["applicable"] == {"docker-baseline": 3, "hardened": 1}
    assert s["errors"] == {"docker-baseline": 1, "hardened": 0}
    assert s["verdict_counts"]["hardened"][NA] == 1


def test_summarise_only_lists_profiles_that_ran():
    s = summarise([_cell("a", "subprocess", SUCCEEDED)])
    assert list(s["breached"]) == ["subprocess"]


def test_build_report_records_meta_and_cells():
    cells = [_cell("a", "subprocess", SUCCEEDED)]
    report = build_report(cells, FakeSandbox(), 3, ("subprocess",))
    assert report["meta"]["profiles"] == ["subprocess"]
    assert report["meta"]["image"] is None  # no Docker profile ran
    assert report["meta"]["session"] == "sess123"
    assert report["cells"][0]["attack"] == "a"
    docker = build_report(cells, FakeSandbox(), 3, ("default", "hardened"))
    assert docker["meta"]["profiles"] == ["docker-baseline", "hardened"]
    assert docker["meta"]["image"] == "fake:img"
