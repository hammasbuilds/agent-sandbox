"""Run every attack under every profile, several repetitions, and score each one.

This is the measurement engine behind the finding. It wires each attack to the harness
infrastructure it needs (a live host beacon for egress, a planted env secret, a host
canary file, an orphan marker), runs it under the subprocess, docker-baseline and hardened
profiles, and scores each run with the attack's check. What a check rests on (the
harness's own observation, a planted token, or the harness-authored payload's report) is
recorded per attack as ``Attack.evidence``.
"""

from __future__ import annotations

import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path

from .attacks.harness import (
    BLOCKED,
    ERROR,
    MIXED,
    NA,
    SUCCEEDED,
    AttackOutcome,
    ChaosContext,
    HostBeacon,
)
from .attacks.registry import Attack, build_attacks
from .profiles import canonical_name, get_profile
from .runner import Sandbox, limits_for
from .types import RunResult, RunSpec

PROFILE_ORDER = ("subprocess", "docker-baseline", "hardened")
VERDICTS = (SUCCEEDED, MIXED, BLOCKED, ERROR, NA)
ORPHAN_WATCH_S = 10.0
# Where the orphan / time-bomb child writes inside a container (a writable tmpfs under
# every profile), so it genuinely lives and only the sandbox's teardown can stop it.
CONTAINER_ORPHAN_MARKER = "/tmp/agsbx-orphan.txt"
# Where Docker Desktop exposes the host's drives inside its Linux VM. A host file is
# reachable from a container at one of these only if that host mount leaked into it.
DOCKER_DESKTOP_HOST_ROOTS = ("/run/desktop/mnt/host", "/host_mnt", "/mnt/host", "/mnt")
# A file outside /work that exists in the image: the symlink target when file-out is read
# inside the container (tmpfs workspace), where a host path means nothing.
IN_CONTAINER_LINK_TARGET = "/etc/passwd"


@dataclass
class Cell:
    attack: str
    category: str
    profile: str
    goal: str
    mechanism: str
    evidence_kind: str
    reps: int
    succeeded: int
    blocked: int
    na: int
    error: int
    verdict: str
    evidence: str
    mean_duration_s: float
    # One {"status", "evidence", "duration_s"} per repetition, so an error or a
    # disagreeing repetition is never hidden behind the cell's verdict.
    per_rep: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {**self.__dict__, "per_rep": [dict(r) for r in self.per_rep]}


@contextmanager
def _ambient_env(pairs: dict[str, str]):
    """Temporarily set host-process env vars (simulates ambient secrets a naive
    inheriting backend would leak). Restored afterwards."""
    saved = {k: os.environ.get(k) for k in pairs}
    os.environ.update(pairs)
    try:
        yield
    finally:
        for k, old in saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def canary_candidates(host_path: str, backend: str) -> list[str]:
    """Paths at which the payload looks for the host canary file.

    The host path itself (what an unisolated process uses), plus, for a container, the
    paths where Docker Desktop exposes that same host file inside its VM. A container can
    read any of them only if a host mount leaked into it.
    """
    out = [host_path]
    m = re.match(r"^([A-Za-z]):[\\/](.*)$", host_path)
    if backend == "docker" and m:
        drive, rest = m.group(1).lower(), m.group(2).replace("\\", "/")
        out += [f"{root}/{drive}/{rest}" for root in DOCKER_DESKTOP_HOST_ROOTS]
    return out


def link_target(profile: str, canary: Path) -> str:
    """Where the symlink attack points out.txt.

    Where file-out is read on the host (subprocess, and docker-baseline's bind-mounted
    /work), a relative climb from the workdir to the host canary: both the workdir and the
    canary live under the system temp dir. Where it is read inside the container (the
    hardened tmpfs workspace, copied out with tar), a file outside /work in the image.
    """
    prof = get_profile(profile)
    if prof.backend == "docker" and limits_for(prof.name).workspace_bytes is not None:
        return IN_CONTAINER_LINK_TARGET
    rel = os.path.relpath(canary, Path(tempfile.gettempdir()))
    return "../" + rel.replace(os.sep, "/")


class ChaosRunner:
    def __init__(self, sandbox: Sandbox, reps: int = 3, scratch: Path | None = None) -> None:
        self.sandbox = sandbox
        self.reps = reps
        self._owns_scratch = scratch is None
        self.scratch = scratch or Path(tempfile.mkdtemp(prefix="agsbx-chaos-"))
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.beacon = HostBeacon().start()

    def close(self) -> None:
        self.beacon.stop()
        if self._owns_scratch:
            shutil.rmtree(self.scratch, ignore_errors=True)

    def __enter__(self) -> ChaosRunner:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- context / env wiring -------------------------------------------------

    def _make_context(self, attack: Attack, profile: str, nonce: str) -> tuple[ChaosContext, dict]:
        backend = get_profile(profile).backend
        secret = "SBXSECRET-" + secrets.token_hex(8)
        canary_token = "SBXCANARY-" + secrets.token_hex(8)

        host_alias = "127.0.0.1" if backend == "subprocess" else "host.docker.internal"
        env: dict[str, str] = {"SBX_NONCE": nonce, "SBX_HOST": host_alias}
        if attack.needs_beacon:
            env["SBX_TCP_PORT"] = str(self.beacon.tcp_port)
            env["SBX_UDP_PORT"] = str(self.beacon.udp_port)
        if attack.needs_canary:
            canary = self.scratch / f"canary-{nonce}.txt"
            canary.write_text(canary_token, encoding="utf-8")
            env["SBX_CANARY_PATHS"] = "\n".join(canary_candidates(str(canary), backend))
            env["SBX_LINK_TARGET"] = link_target(profile, canary)
        if attack.outlives_run:
            env["SBX_ORPHAN_MARKER"] = (
                str(self.scratch / f"orphan-{nonce}.txt")
                if backend == "subprocess"
                else CONTAINER_ORPHAN_MARKER
            )

        ctx = ChaosContext(
            nonce=nonce,
            secret=secret,
            canary_token=canary_token,
            backend=backend,
            beacon=self.beacon,
        )
        return ctx, env

    # -- single execution -----------------------------------------------------

    def _run_once(self, attack: Attack, profile: str) -> tuple[AttackOutcome, RunResult]:
        backend = get_profile(profile).backend
        if attack.linux_only and backend == "subprocess" and not sys.platform.startswith("linux"):
            outcome = AttackOutcome(
                NA, f"Linux-only attack; the subprocess backend runs on {sys.platform}"
            )
            return outcome, RunResult("subprocess", profile, None, "", "", 0.0, False)

        nonce = uuid.uuid4().hex
        ctx, env = self._make_context(attack, profile, nonce)
        limits = limits_for(profile)
        if attack.wall_override is not None:
            limits = limits.with_(wall_seconds=attack.wall_override)
        spec = RunSpec(
            code=attack.code,
            stdin="",
            env=env,
            files_out=attack.files_out,
            limits=limits,
            count_lingering=attack.outlives_run and backend == "docker",
        )

        ambient: dict[str, str] = {}
        if attack.needs_secret:
            ambient["SBX_SECRET"] = ctx.secret  # only an inheriting backend leaks this

        with _ambient_env(ambient):
            result = self.sandbox.run_spec(spec, profile)

        if result.error:
            return AttackOutcome(ERROR, result.error), result

        if attack.outlives_run:
            outcome = self._resolve_orphan(attack, ctx, env, result)
        else:
            outcome = attack.check(result, ctx)
        return outcome, result

    def _resolve_orphan(
        self, attack: Attack, ctx: ChaosContext, env: dict, result: RunResult
    ) -> AttackOutcome:
        if attack.name == "time_bomb" and not result.timed_out:
            return AttackOutcome(ERROR, "the program was not ended by the wall-clock timeout")
        if ctx.backend == "docker":
            name = _container_name(result.argv)
            exists = None if name is None else _container_exists(name)
            return _docker_orphan_check(result, exists)

        # Subprocess: the detached child rewrites a host marker every 0.2s. On a loaded
        # host it can take seconds just to start, so poll (up to ORPHAN_WATCH_S) for the
        # marker's content to change AFTER run() returned -- two distinct observations
        # prove a live process outlived the run.
        marker = Path(env["SBX_ORPHAN_MARKER"])
        seen: set[str] = set()
        deadline = time.monotonic() + ORPHAN_WATCH_S
        while time.monotonic() < deadline and len(seen) < 2:
            with suppress(OSError):
                seen.add(marker.read_text(encoding="utf-8"))
            time.sleep(0.25)

        # Clean up: kill only the exact child pid the attack printed (and its own tree).
        m = re.search(r"ORPHAN_PID\s+(\d+)", result.stdout)
        if m:
            _kill_pid(int(m.group(1)))
        with suppress(OSError):
            marker.unlink()
        return _subprocess_orphan_verdict(len(seen), spawned=m is not None)

    # -- aggregation ----------------------------------------------------------

    def run_cell(self, attack: Attack, profile: str) -> Cell:
        profile = canonical_name(profile)  # "default" -> "docker-baseline", everywhere
        counts = {SUCCEEDED: 0, BLOCKED: 0, NA: 0, ERROR: 0}
        per_rep: list[dict] = []
        for _ in range(self.reps):
            outcome, result = self._run_once(attack, profile)
            counts[outcome.status] += 1
            per_rep.append(
                {
                    "status": outcome.status,
                    "evidence": outcome.evidence,
                    "duration_s": round(result.duration_s, 3),
                }
            )

        verdict = _verdict(counts)
        durations = [r["duration_s"] for r in per_rep]
        return Cell(
            attack=attack.name,
            category=attack.category,
            profile=profile,
            goal=attack.goal,
            mechanism=attack.mechanism,
            evidence_kind=attack.evidence,
            reps=self.reps,
            succeeded=counts[SUCCEEDED],
            blocked=counts[BLOCKED],
            na=counts[NA],
            error=counts[ERROR],
            verdict=verdict,
            evidence=_cell_evidence(verdict, per_rep),
            mean_duration_s=round(sum(durations) / len(durations), 3) if durations else 0.0,
            per_rep=per_rep,
        )

    def run_all(self, profiles: tuple[str, ...] = PROFILE_ORDER) -> list[Cell]:
        profiles = tuple(dict.fromkeys(canonical_name(p) for p in profiles))
        # Decide Docker availability ONCE, up front, and refuse rather than silently drop
        # the Docker columns from the matrix.
        needs_docker = [p for p in profiles if get_profile(p).backend == "docker"]
        if needs_docker and not self.sandbox.docker_available():
            raise RuntimeError(f"profiles {needs_docker} need a running Docker engine")
        return [self.run_cell(a, p) for a in build_attacks() for p in profiles]


def _container_name(argv: tuple[str, ...]) -> str | None:
    for i, tok in enumerate(argv[:-1]):
        if tok == "--name":
            return argv[i + 1]
    return None


def _container_exists(name: str) -> bool | None:
    """Whether a container of that exact name exists in any state; None if unknown."""
    try:
        r = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"name=^{name}$"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return bool(r.stdout.strip()) if r.returncode == 0 else None


def _docker_orphan_check(result: RunResult, exists_after: bool | None) -> AttackOutcome:
    """Score a Docker run of orphan_survivor / time_bomb.

    The harness counted the live processes left in the container when the program exited,
    before teardown (``result.lingering_processes``), and then checked that the container
    is gone. A child that was alive at exit and gone afterwards was stopped by the
    harness's teardown (``docker rm --force``), not by a Docker flag. If no child was
    alive at exit, the teardown was never exercised, so there is nothing to credit.
    """
    if "ORPHAN_PID" not in result.stdout:
        return AttackOutcome(ERROR, f"payload never spawned its child: {_tail(result)}")
    if exists_after is None:
        return AttackOutcome(ERROR, "could not check whether the container still exists")
    if exists_after:
        return AttackOutcome(SUCCEEDED, "the run's container still exists after run() returned")
    n = result.lingering_processes
    if n is None:
        return AttackOutcome(ERROR, "could not count processes in the container before teardown")
    if n == 0:
        return AttackOutcome(
            ERROR, "the child was not alive when the program exited, so teardown was not tested"
        )
    return AttackOutcome(
        BLOCKED,
        f"{n} process(es) outlived the program inside the container; the harness's teardown "
        "removed the container with them",
    )


def _subprocess_orphan_verdict(distinct_marker_values: int, *, spawned: bool) -> AttackOutcome:
    if distinct_marker_values >= 2:
        return AttackOutcome(
            SUCCEEDED, "a detached child kept rewriting its host marker after the run returned"
        )
    if not spawned:
        return AttackOutcome(ERROR, "payload never reported spawning its child")
    return AttackOutcome(BLOCKED, f"no live process seen within {ORPHAN_WATCH_S:.0f}s")


def _tail(result: RunResult) -> str:
    text = (result.stdout.strip() or result.stderr.strip()).splitlines()
    return (text[-1] if text else f"exit={result.exit_code}")[:120]


def _verdict(counts: dict[str, int]) -> str:
    """Cell verdict from per-repetition outcomes.

    n/a repetitions are set aside. If every other repetition agrees, that is the verdict.
    If they disagree, the cell is ``mixed`` when at least one repetition succeeded (a
    breach is never hidden) and ``error`` otherwise (e.g. blocked + error: the evidence is
    incomplete, so the cell is not scored as blocked).
    """
    live = {k: v for k, v in counts.items() if k != NA and v > 0}
    if not live:
        return NA
    if len(live) == 1:
        return next(iter(live))
    return MIXED if SUCCEEDED in live else ERROR


def _cell_evidence(verdict: str, per_rep: list[dict]) -> str:
    """Evidence that matches the verdict: a breach for succeeded/mixed, else the first
    repetition with the verdict's own status."""
    want = SUCCEEDED if verdict == MIXED else verdict
    for rep in per_rep:
        if rep["status"] == want:
            return rep["evidence"]
    return per_rep[0]["evidence"] if per_rep else ""


def _kill_pid(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, timeout=15)
    else:  # pragma: no cover
        import signal

        with suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


def summarise(cells: list[Cell]) -> dict:
    """A compact matrix: attack -> {profile: verdict}, plus per-profile verdict counts.

    ``breached`` counts cells where every scored repetition succeeded; ``breached_any_rep``
    adds the ``mixed`` cells, where at least one did. ``applicable`` is every cell that was
    scored (succeeded, mixed or blocked); errors and n/a are counted separately.
    """
    matrix: dict[str, dict[str, str]] = {}
    profiles: list[str] = []
    for c in cells:
        matrix.setdefault(c.attack, {})[c.profile] = c.verdict
        if c.profile not in profiles:
            profiles.append(c.profile)
    counts = {p: dict.fromkeys(VERDICTS, 0) for p in profiles}
    for c in cells:
        counts[c.profile][c.verdict] += 1
    return {
        "matrix": matrix,
        "verdict_counts": counts,
        "breached": {p: n[SUCCEEDED] for p, n in counts.items()},
        "breached_any_rep": {p: n[SUCCEEDED] + n[MIXED] for p, n in counts.items()},
        "applicable": {p: n[SUCCEEDED] + n[MIXED] + n[BLOCKED] for p, n in counts.items()},
        "errors": {p: n[ERROR] for p, n in counts.items()},
    }


def build_report(cells: list[Cell], sandbox: Sandbox, reps: int, profiles: tuple[str, ...]) -> dict:
    uses_docker = any(get_profile(p).backend == "docker" for p in profiles)
    return {
        "meta": {
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reps": reps,
            "image": sandbox.image if uses_docker else None,
            "session": sandbox.session,
            "host": {
                "platform": platform.platform(),
                "python": platform.python_version(),
            },
            "profiles": [canonical_name(p) for p in profiles],
        },
        "summary": summarise(cells),
        "cells": [c.as_dict() for c in cells],
    }


def write_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
