"""Command-line interface: run code under a profile, list profiles, run the chaos suite,
measure latency, and clean up leftover containers.

Exit codes: ``run`` returns the program's own exit code, 124 when the wall-clock budget
ended it, and 3 when the sandbox itself could not run it (e.g. Docker down). A refused
command (bad input, Docker missing for chaos/latency/cleanup, or an existing results file
without --out/--force) exits 1 with an ``agent-sandbox: error:`` line; argparse usage
errors exit 2.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .profiles import PROFILES, get_profile
from .runner import Sandbox, enforced_limits, limits_for
from .types import MAX_WALL_SECONDS, RunResult, check_files_in_layout, check_workdir_path

SUBPROCESS_WARNING = (
    "WARNING: profile 'subprocess' runs the code directly on this host, with no isolation: "
    "it can read your files and environment variables, use your network and leave "
    "processes running. Use it only for code you trust."
)


def _positive_int(text: str) -> int:
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {text!r}") from None
    if v < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {v}")
    return v


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
    p.add_argument(
        "--timeout",
        type=float,
        default=None,
        help=f"wall-clock seconds, more than 0 and at most {MAX_WALL_SECONDS:g}",
    )
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


def _fail(msg: str) -> SystemExit:
    return SystemExit(f"agent-sandbox: error: {msg}")


def _parse_env(pairs: list[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for item in pairs:
        if "=" not in item:
            raise _fail(f"bad --env {item!r}; expected KEY=VALUE")
        k, v = item.split("=", 1)
        env[k] = v
    return env


def _parse_files_in(items: list[str]) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for item in items:
        # Split on the LAST ':' that is not a Windows drive colon (C:\...).
        local, rel = item, None
        idx = item.rfind(":")
        drive_colon = idx == 1 and item[0].isalpha() and item[2:3] in ("\\", "/")
        if idx > 0 and not drive_colon:
            local, rel = item[:idx], item[idx + 1 :]
        path = Path(local)
        if not path.is_file():
            raise _fail(f"--file-in: no such file: {local}")
        name = rel or path.name
        try:
            check_workdir_path(name)
        except ValueError as e:
            raise _fail(f"--file-in: bad destination {name!r}: {e}") from None
        if name in files:
            raise _fail(f"--file-in: two inputs go to the same destination {name!r}")
        files[name] = path.read_bytes()
    try:
        check_files_in_layout(tuple(files), code_given=True)
    except ValueError as e:
        raise _fail(f"--file-in: {e}") from None
    return files


def _parse_files_out(items: list[str]) -> tuple[str, ...]:
    for rel in items:
        try:
            check_workdir_path(rel)
        except ValueError:
            raise _fail(
                f"--file-out: path must be relative and inside the workdir: {rel!r}"
            ) from None
    return tuple(items)


def _emit(result: RunResult, as_json: bool) -> int:
    if as_json:
        payload = {
            "backend": result.backend,
            "profile": result.profile,
            "exit_code": result.exit_code,
            "duration_s": round(result.duration_s, 3),
            "program_s": None if result.program_s is None else round(result.program_s, 3),
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
        if not as_json:
            print(f"agent-sandbox: error: {result.error}", file=sys.stderr)
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
            raise _fail(f"no such file: {path}")
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
            raise _fail(f"bad --timeout: {e}") from None

    env = _parse_env(args.env)
    files_in = _parse_files_in(args.file_in)
    files_out = _parse_files_out(args.file_out)
    if get_profile(args.profile).backend == "subprocess":
        print(SUBPROCESS_WARNING, file=sys.stderr)

    result = Sandbox().run(
        code=code,
        profile=args.profile,
        stdin=stdin,
        env=env,
        files_in=files_in,
        files_out=files_out,
        limits=limits,
    )
    return _emit(result, args.json)


def _fmt_limit(name: str, value: object) -> str:
    if name.endswith("_bytes"):
        assert isinstance(value, int)
        mb = value / (1 << 20)
        return f"{name.removesuffix('_bytes')}={mb:g}m"
    if name == "wall_seconds":
        return f"wall={value}s"
    return f"{name}={value}"


def _cmd_profiles(args: argparse.Namespace) -> int:
    for name, prof in PROFILES.items():
        print(f"{name:15s} [{prof.backend}]  {prof.description}")
        enforced = enforced_limits(name)
        print(f"{'':15s} enforced here: " + " ".join(_fmt_limit(k, v) for k, v in enforced.items()))
        if prof.backend == "docker" and "memory_bytes" in enforced:
            print(f"{'':15s} swap: disabled (--memory-swap = --memory)")
    return 0


def _require_docker(sandbox: Sandbox, what: str) -> None:
    if not sandbox.docker_available():
        raise SystemExit(
            f"agent-sandbox: error: {what} needs a running Docker engine, and none was found "
            "(is Docker Desktop / dockerd running?)"
        )


def _output_path(out: str | None, default: str, force: bool) -> Path:
    """Refuse to overwrite a committed result unless the caller asked for it explicitly."""
    if out is not None:
        return Path(out)
    path = Path(default)
    if path.exists() and not force:
        raise _fail(
            f"{path} already exists; pass --out PATH to write elsewhere or --force to overwrite"
        )
    return path


def _cmd_chaos(args: argparse.Namespace) -> int:
    out = _output_path(args.out, "results/chaos.json", args.force)
    from .chaos import PROFILE_ORDER, ChaosRunner, build_report, write_report

    profiles = tuple(dict.fromkeys(args.profiles)) if args.profiles else PROFILE_ORDER
    sandbox = Sandbox()
    docker_profiles = [p for p in profiles if get_profile(p).backend == "docker"]
    if docker_profiles:
        _require_docker(sandbox, f"chaos with {', '.join(docker_profiles)}")
    if "subprocess" in profiles:
        print(SUBPROCESS_WARNING, file=sys.stderr)

    runner = ChaosRunner(sandbox, reps=args.reps)
    try:
        cells = runner.run_all(profiles)
    finally:
        runner.close()
    report = build_report(cells, sandbox, args.reps, profiles)
    write_report(report, out)
    summary = report["summary"]
    print(f"wrote {out}")
    for p, counts in summary["verdict_counts"].items():
        print(
            f"  {p:15s} breached {summary['breached'][p]}/{summary['applicable'][p]} applicable "
            f"(in any rep: {summary['breached_any_rep'][p]}); "
            f"error {counts['error']}, n/a {counts['n/a']}"
        )
    return 0


def _cmd_latency(args: argparse.Namespace) -> int:
    out = _output_path(args.out, "results/latency.json", args.force)
    sandbox = Sandbox()
    _require_docker(sandbox, "latency")
    from .latency import build_latency_report, format_latency_report, write_latency_report

    report = build_latency_report(sandbox, rounds=args.rounds, seed=args.seed)
    write_latency_report(report, out)
    print(f"wrote {out}")
    print(format_latency_report(report))
    return 0


def _cmd_cleanup(args: argparse.Namespace) -> int:
    sandbox = Sandbox()
    _require_docker(sandbox, "cleanup")
    try:
        if args.session:
            n = sandbox.cleanup(args.session)
            what = f"container(s) of session {args.session}"
        else:
            n = sandbox.remove_stopped()
            what = "stopped agent-sandbox container(s)"
    except RuntimeError as e:
        raise _fail(str(e)) from None
    print(f"removed {n} {what}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-sandbox",
        description="Run AI-generated code under named hardening profiles, "
        "and measure what each profile actually stops.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    _add_run(sub)

    sub.add_parser("profiles", help="list hardening profiles and the limits enforced on this OS")

    c = sub.add_parser("chaos", help="run the chaos/escape suite across profiles")
    c.add_argument("--reps", type=_positive_int, default=3, help="repetitions per attack/profile")
    c.add_argument("--out", default=None, help="output JSON path (default: results/chaos.json)")
    c.add_argument("--force", action="store_true", help="overwrite the default output file")
    c.add_argument(
        "--profiles",
        nargs="+",
        choices=list(PROFILES),
        help="subset of profiles to test (default: all)",
    )

    latency = sub.add_parser(
        "latency",
        help="measure per-profile latency: counterbalanced order, paired robust analysis",
    )
    latency.add_argument("--rounds", type=_positive_int, default=100, help="measured rounds")
    latency.add_argument("--seed", type=int, default=0, help="seed for the per-round order")
    latency.add_argument(
        "--out", default=None, help="output JSON path (default: results/latency.json)"
    )
    latency.add_argument("--force", action="store_true", help="overwrite the default output file")

    cl = sub.add_parser(
        "cleanup",
        help="remove leftover agent-sandbox containers (by default only stopped ones)",
        description="Remove leftover agent-sandbox containers. By default only containers "
        "that have already stopped are removed, so a run in progress in another process is "
        "never touched. A harness that crashed leaves its container idling until its "
        "keep-alive expires; it is removable after that.",
    )
    cl.add_argument(
        "--session",
        default=None,
        help="instead, remove every container (running or not) labelled with this session id",
    )
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
