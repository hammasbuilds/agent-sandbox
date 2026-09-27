"""Run every attack under every profile, several repetitions, and score them objectively.

This is the measurement engine behind the finding. It wires each attack to the harness
infrastructure it needs (a live host beacon for egress, a planted env secret, a host
canary file, an orphan marker outside the workdir), runs it under the subprocess, default
and hardened profiles, and lets the harness -- never the attack -- decide each outcome.
"""

from __future__ import annotations

import json
import os
import platform
import re
import secrets
import subprocess
import tempfile
import time
import uuid
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from .attacks.harness import BLOCKED, ERROR, NA, SUCCEEDED, AttackOutcome, ChaosContext, HostBeacon
from .attacks.registry import Attack, build_attacks
from .profiles import get_profile
from .runner import Sandbox, limits_for
from .types import RunResult, RunSpec

PROFILE_ORDER = ("subprocess", "default", "hardened")
ORPHAN_WATCH_S = 10.0


@dataclass
class Cell:
    attack: str
    category: str
    profile: str
    goal: str
    mechanism: str
    reps: int
    succeeded: int
    blocked: int
    na: int
    error: int
    verdict: str
    evidence: str
    mean_duration_s: float

    def as_dict(self) -> dict:
        return self.__dict__.copy()


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


class ChaosRunner:
    def __init__(self, sandbox: Sandbox, reps: int = 3, scratch: Path | None = None) -> None:
        self.sandbox = sandbox
        self.reps = reps
        self.scratch = scratch or Path(tempfile.mkdtemp(prefix="agsbx-chaos-"))
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.beacon = HostBeacon().start()

    def close(self) -> None:
        self.beacon.stop()

    # -- context / env wiring -------------------------------------------------

    def _make_context(self, attack: Attack, profile: str, nonce: str) -> tuple[ChaosContext, dict]:
        backend = get_profile(profile).backend
        host_alias = "127.0.0.1" if backend == "subprocess" else "host.docker.internal"
        secret = "SBXSECRET-" + secrets.token_hex(8)
        canary_token = "SBXCANARY-" + secrets.token_hex(8)
        canary_path = str(self.scratch / f"canary-{nonce}.txt")

        env: dict[str, str] = {"SBX_NONCE": nonce, "SBX_HOST": host_alias}
        if attack.needs_beacon:
            env["SBX_TCP_PORT"] = str(self.beacon.tcp_port)
            env["SBX_UDP_PORT"] = str(self.beacon.udp_port)
        if attack.needs_canary:
            Path(canary_path).write_text(canary_token, encoding="utf-8")
            env["SBX_CANARY_PATH"] = canary_path
            # Both the backend's workdir and this scratch dir are created in the system
            # temp dir, so from the workdir the canary is reachable as ../<scratch>/<file>.
            if self.scratch.parent.resolve() == Path(tempfile.gettempdir()).resolve():
                env["SBX_CANARY_REL"] = f"../{self.scratch.name}/{Path(canary_path).name}"
        if attack.name == "disk_fill":
            env["SBX_DISK_DIR"] = str(self.scratch) if backend == "subprocess" else "/var/tmp"
        if attack.name == "orphan_survivor":
            # Host path for subprocess; a writable in-container path for Docker, so the
            # child genuinely lives and only the sandbox's teardown can stop it.
            env["SBX_ORPHAN_MARKER"] = (
                str(self.scratch / f"orphan-{nonce}.txt")
                if backend == "subprocess"
                else "/tmp/agsbx-orphan.txt"
            )

        ctx = ChaosContext(
            nonce=nonce,
            secret=secret,
            canary_path=canary_path,
            canary_token=canary_token,
            backend=backend,
            host_alias=host_alias,
            beacon=self.beacon,
        )
        return ctx, env

    # -- single execution -----------------------------------------------------

    def _run_once(self, attack: Attack, profile: str) -> tuple[AttackOutcome, RunResult]:
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
        )

        ambient: dict[str, str] = {}
        if attack.needs_secret:
            ambient["SBX_SECRET"] = ctx.secret  # only an inheriting backend leaks this

        with _ambient_env(ambient):
            result = self.sandbox.run_spec(spec, profile)

        if result.error:
            return AttackOutcome(ERROR, result.error), result

        if attack.name == "orphan_survivor":
            outcome = self._resolve_orphan(ctx, env, result)
        else:
            outcome = attack.check(result, ctx)
        return outcome, result

    def _resolve_orphan(self, ctx: ChaosContext, env: dict, result: RunResult) -> AttackOutcome:
        if ctx.backend == "docker":
            return _docker_orphan_check(result)

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
        survived = len(seen) >= 2

        # Clean up: kill only the exact child pid the attack printed.
        m = re.search(r"ORPHAN_PID\s+(\d+)", result.stdout)
        if m:
            _kill_pid(int(m.group(1)))
        with suppress(OSError):
            marker.unlink()

        if survived:
            return AttackOutcome(
                SUCCEEDED, "a detached child kept rewriting its marker after the run returned"
            )
        return AttackOutcome(BLOCKED, f"no live process seen within {ORPHAN_WATCH_S:.0f}s")

    # -- aggregation ----------------------------------------------------------

    def run_cell(self, attack: Attack, profile: str) -> Cell:
        counts = {SUCCEEDED: 0, BLOCKED: 0, NA: 0, ERROR: 0}
        success_ev = ""
        any_ev = ""
        durations: list[float] = []
        for _ in range(self.reps):
            outcome, result = self._run_once(attack, profile)
            counts[outcome.status] = counts.get(outcome.status, 0) + 1
            durations.append(result.duration_s)
            if outcome.status == SUCCEEDED and not success_ev:
                success_ev = outcome.evidence
            if not any_ev:
                any_ev = outcome.evidence

        # Show evidence that matches the verdict: a breach message when any rep breached.
        evidence = success_ev or any_ev
        verdict = _verdict(counts, self.reps)
        mean = sum(durations) / len(durations) if durations else 0.0
        return Cell(
            attack=attack.name,
            category=attack.category,
            profile=profile,
            goal=attack.goal,
            mechanism=attack.mechanism,
            reps=self.reps,
            succeeded=counts[SUCCEEDED],
            blocked=counts[BLOCKED],
            na=counts[NA],
            error=counts[ERROR],
            verdict=verdict,
            evidence=evidence,
            mean_duration_s=round(mean, 3),
        )

    def run_all(self, profiles: tuple[str, ...] = PROFILE_ORDER) -> list[Cell]:
        attacks = build_attacks()
        # Decide Docker availability ONCE, up front. Re-checking per cell lets a busy
        # daemon flap the answer and silently drop columns from the matrix.
        docker_ok = self.sandbox.docker_available()
        cells: list[Cell] = []
        for attack in attacks:
            for profile in profiles:
                if get_profile(profile).backend == "docker" and not docker_ok:
                    continue
                cells.append(self.run_cell(attack, profile))
        return cells


def _container_name(argv: tuple[str, ...]) -> str | None:
    for i, tok in enumerate(argv[:-1]):
        if tok == "--name":
            return argv[i + 1]
    return None


def _docker_orphan_check(result: RunResult) -> AttackOutcome:
    """Host-side check: is the run's container (and so anything inside it) still alive
    after run() returned? When PID 1 exits, the kernel kills every process in the
    container's PID namespace, so a detached child cannot outlive it."""
    name = _container_name(result.argv)
    if name is None:
        return AttackOutcome(ERROR, "could not identify the run's container")
    alive = False
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        r = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"name=^{name}$"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        alive = bool(r.stdout.strip())
        if alive:
            break
        time.sleep(0.5)
    if alive:
        return AttackOutcome(SUCCEEDED, f"container {name} still running after the run returned")
    if "ORPHAN_PID" not in result.stdout:
        return AttackOutcome(ERROR, "payload never spawned its child")
    return AttackOutcome(
        BLOCKED, "child was spawned, but the container (its PID namespace) was gone on return"
    )


def _verdict(counts: dict[str, int], reps: int) -> str:
    if counts.get(NA, 0) == reps:
        return NA
    if counts.get(ERROR, 0) == reps:
        return ERROR
    if counts.get(SUCCEEDED, 0) > 0:  # any breach across reps counts as a breach
        return SUCCEEDED
    return BLOCKED


def _kill_pid(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=10)
    else:  # pragma: no cover
        import signal

        with suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


def summarise(cells: list[Cell]) -> dict:
    """A compact matrix: attack -> {profile: verdict} plus per-profile breach counts."""
    matrix: dict[str, dict[str, str]] = {}
    for c in cells:
        matrix.setdefault(c.attack, {})[c.profile] = c.verdict
    breaches = {p: 0 for p in PROFILE_ORDER}
    applicable = {p: 0 for p in PROFILE_ORDER}
    for c in cells:
        if c.verdict in (SUCCEEDED, BLOCKED):
            applicable[c.profile] += 1
        if c.verdict == SUCCEEDED:
            breaches[c.profile] += 1
    return {"matrix": matrix, "breaches": breaches, "applicable": applicable}


def build_report(cells: list[Cell], sandbox: Sandbox, reps: int, image: str) -> dict:
    return {
        "meta": {
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reps": reps,
            "image": image,
            "docker_available": sandbox.docker_available(),
            "host": {
                "platform": platform.platform(),
                "python": platform.python_version(),
            },
            "profiles": list(PROFILE_ORDER),
        },
        "summary": summarise(cells),
        "cells": [c.as_dict() for c in cells],
    }


def write_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
