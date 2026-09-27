"""Demo: run ordinary code in the sandbox, then watch five attacks meet three profiles.

Known-answer input:
  1. A normal task -- sum the integers on stdin -- must print 15 and exit 0.
  2. Five attacks whose outcome the harness verifies for itself (not the attacker):
       env_secret_read  -- only the inheriting subprocess baseline leaks the host secret
       orphan_survivor  -- only the subprocess baseline lets a detached child outlive the run
       tcp_egress       -- plain Docker still reaches the network; hardened does not
       run_as_root      -- plain Docker runs your code as uid 0; hardened runs as 65534
       memory_bomb      -- plain Docker lets it allocate 300 MB; hardened OOM-kills it
If Docker is not running, only the subprocess column is shown.

Run:  uv run python demo.py
"""

from __future__ import annotations

from agent_sandbox import Sandbox
from agent_sandbox.attacks.registry import build_attacks
from agent_sandbox.chaos import ChaosRunner

SHOWCASE = ["env_secret_read", "orphan_survivor", "tcp_egress", "run_as_root", "memory_bomb"]


def main() -> None:
    sandbox = Sandbox()
    docker = sandbox.docker_available()

    print("=" * 76)
    print("1) A normal task: sum the integers on stdin (known answer: 15)")
    print("=" * 76)
    r = sandbox.run(
        code="import sys; print(sum(int(x) for x in sys.stdin.read().split()))",
        profile="hardened" if docker else "subprocess",
        stdin="1 2 3 4 5",
    )
    print(f"profile   : {r.profile}")
    print(f"stdout    : {r.stdout.strip()!r}")
    print(f"exit_code : {r.exit_code}")

    print()
    print("=" * 76)
    print("2) Five attacks x three profiles -- outcome decided by the harness")
    print("=" * 76)
    profiles = ["subprocess"] + (["default", "hardened"] if docker else [])
    by_name = {a.name: a for a in build_attacks()}
    runner = ChaosRunner(sandbox, reps=1)
    try:
        cells = {(n, p): runner.run_cell(by_name[n], p) for n in SHOWCASE for p in profiles}
    finally:
        runner.close()

    header = f"{'attack':17s}" + "".join(f"{p:>12s}" for p in profiles)
    print(header)
    print("-" * len(header))
    for n in SHOWCASE:
        print(f"{n:17s}" + "".join(f"{cells[(n, p)].verdict:>12s}" for p in profiles))
    print()
    print("succeeded = the sandbox did NOT contain it; blocked = it held.")
    if not docker:
        print("(Docker engine not detected -- only the unsafe subprocess baseline was run.)")
        return
    for p in ("default", "hardened"):
        print(f"\nEvidence under {p}:")
        for n in SHOWCASE:
            c = cells[(n, p)]
            print(f"  {n:17s} {c.verdict:10s} {c.evidence}")


if __name__ == "__main__":
    main()
