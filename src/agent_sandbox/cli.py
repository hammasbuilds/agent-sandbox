"""Command-line interface: run code under a profile, list profiles, run the chaos suite,
measure latency, and clean up leftover containers.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .profiles import PROFILES
from .runner import Sandbox, limits_for
from .types import RunResult


def _add_run(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("run", help="run code or a file under a hardening profile")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--code", help="inline source to run")
    src.add_argument("--file", help="path to a .py file to run")
    p.add_argument(
        "--profile",
        default="hardened",
        choices=list(PROFILES),
        help="hardening profile (default: hardened)",
    )
    p.add_argument("--timeout", type=float, default=None, help="wall-clock seconds")
    p.add_argument(
        "--stdin",
        default=None,
        help="stdin text; use '-' to read stdin from the terminal",
    )
    p.add_argument("--env", action="append", default=[], metavar="K=V", help="env var (repeatable)")
    p.add_argument(
        "--file-in",
        action="append",
        default=[],
        metavar="LOCAL[:REL]",
        help="copy a local file into the workdir, optionally renamed to REL (repeatable)",
    )
    p.add_argument(
        "--file-out",
        action="append",
        default=[],
        metavar="REL",
        help="workdir-relative file to read back after the run (repeatable)",
    )
    p.add_argument("--json", action="store_true", help="emit the full result as JSON")


def _parse_env(pairs: list[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in pairs:
        if "=" not in item:
            raise SystemExit(f"bad --env {item!r}; expected KEY=VALUE")
        k, v = item.split("=", 1)
        env[k] = v
    return env


def _parse_files_in(items: list[str]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for item in items:
        # Split on the LAST ':' that is not a Windows drive colon (C:\...).
        local, rel = item, None
        idx = item.rfind(":")
        if idx > 1:
            local, rel = item[:idx], item[idx + 1 :]
        path = Path(local)
        if not path.is_file():
            raise SystemExit(f"--file-in: no such file: {local}")
        name = rel or path.name
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise SystemExit(f"--file-in: destination must stay inside the workdir: {name}")
        files[name] = path.read_bytes()
    return files


def _emit(result: RunResult, as_json: bool) -> int:
    if as_json:
        payload = {
            "backend": result.backend,
            "profile": result.profile,
            "exit_code": result.exit_code,
            "duration_s": round(result.duration_s, 3),
            "timed_out": result.timed_out,
            "out_of_memory": result.out_of_memory,
            "output_truncated": result.output_truncated,
            "error": result.error,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "files_out": {k: v.decode("utf-8", "replace") for k, v in result.files_out.items()},
        }
        print(json.dumps(payload, indent=2))
    else:
        sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        print(f"\n[{result.backend}/{result.profile}] {result.summary()}", file=sys.stderr)
    if result.error:
        return 3
    if result.timed_out:
        return 124
    return result.exit_code if result.exit_code is not None else 1


def _cmd_run(args: argparse.Namespace) -> int:
    if args.code is not None:
        code = args.code
    else:
        path = Path(args.file)
        if not path.is_file():
            raise SystemExit(f"no such file: {path}")
        code = path.read_text(encoding="utf-8")

    stdin = ""
    if args.stdin == "-":
        stdin = sys.stdin.read()
    elif args.stdin is not None:
        stdin = args.stdin

    limits = limits_for(args.profile)
    if args.timeout is not None:
        try:
            limits = limits.with_(wall_seconds=args.timeout)
        except ValueError as e:
            raise SystemExit(f"bad --timeout: {e}") from None

    sandbox = Sandbox()
    result = sandbox.run(
        code=code,
        profile=args.profile,
        stdin=stdin,
        env=_parse_env(args.env),
        files_in=_parse_files_in(args.file_in),
        files_out=tuple(args.file_out),
        limits=limits,
    )
    return _emit(result, args.json)


def _cmd_profiles(args: argparse.Namespace) -> int:
    for name, prof in PROFILES.items():
        lim = limits_for(name)
        print(f"{name:11s} [{prof.backend}]  {prof.description}")
        print(
            f"            limits: wall={lim.wall_seconds}s "
            f"mem={_mb(lim.memory_bytes)} pids={lim.pids} cpus={lim.cpus} "
            f"fsize={_mb(lim.fsize_bytes)}"
        )
    return 0


def _mb(v: int | None) -> str:
    return "-" if v is None else f"{v // (1 << 20)}m"


def _cmd_chaos(args: argparse.Namespace) -> int:
    from .chaos import ChaosRunner, build_report, write_report

    sandbox = Sandbox()
    runner = ChaosRunner(sandbox, reps=args.reps)
    try:
        profiles = tuple(args.profiles) if args.profiles else None
        cells = runner.run_all(profiles) if profiles else runner.run_all()
    finally:
        runner.close()
    report = build_report(cells, sandbox, args.reps, sandbox._docker.image)
    out = Path(args.out)
    write_report(report, out)
    b = report["summary"]["breaches"]
    a = report["summary"]["applicable"]
    print(f"wrote {out}")
    for p in ("subprocess", "default", "hardened"):
        if a.get(p):
            print(f"  {p:11s} breached {b[p]}/{a[p]} applicable attacks")
    return 0


def _cmd_latency(args: argparse.Namespace) -> int:
    from .latency import build_latency_report, write_latency_report

    sandbox = Sandbox()
    report = build_latency_report(sandbox, rounds=args.rounds)
    out = Path(args.out)
    write_latency_report(report, out)
    print(f"wrote {out}")
    for name, s in report["profiles"].items():
        print(f"  {name:11s} first={s['first_run_s']}s median={s['median_s']}s min={s['min_s']}s")
    ov = report["hardening_overhead"]
    if ov:
        lo, hi = ov["paired_diff_ci95_s"]
        print(
            f"  hardened - default (paired median) = {ov['paired_diff_median_s']}s "
            f"[95% CI {lo}, {hi}]; hardened slower in {ov['hardened_slower_in_rounds']}"
            f"/{ov['rounds']} rounds"
        )
    return 0


def _cmd_cleanup(args: argparse.Namespace) -> int:
    n = Sandbox().cleanup()
    print(f"removed {n} leftover agent-sandbox container(s)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-sandbox",
        description="Run AI-generated code under named hardening profiles, "
        "and measure what each profile actually stops.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    _add_run(sub)

    sub.add_parser("profiles", help="list hardening profiles and their limits")

    c = sub.add_parser("chaos", help="run the chaos/escape suite across profiles")
    c.add_argument("--reps", type=int, default=3, help="repetitions per attack/profile")
    c.add_argument("--out", default="results/chaos.json", help="output JSON path")
    c.add_argument(
        "--profiles",
        nargs="+",
        choices=list(PROFILES),
        help="subset of profiles to test (default: all)",
    )

    latency = sub.add_parser(
        "latency", help="measure per-profile latency, interleaved to cancel host-load drift"
    )
    latency.add_argument("--rounds", type=int, default=10, help="interleaved rounds")
    latency.add_argument("--out", default="results/latency.json", help="output JSON path")

    sub.add_parser("cleanup", help="remove leftover agent-sandbox containers")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    dispatch = {
        "run": _cmd_run,
        "profiles": _cmd_profiles,
        "chaos": _cmd_chaos,
        "latency": _cmd_latency,
        "cleanup": _cmd_cleanup,
    }
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
