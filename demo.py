"""Demo: run ordinary code in the sandbox, then watch four attacks meet two profiles.

Known-answer input:
  * A normal task -- sum the integers on stdin -- must return the right number and exit 0.
  * Four attacks whose outcome the harness verifies for itself. Under the unsafe
    subprocess baseline several succeed; under the hardened Docker profile they are
    contained. If Docker is not running, the Docker column is skipped.

Run:  uv run python demo.py
"""

from __future__ import annotations

from agent_sandbox import Sandbox
from agent_sandbox.attacks.registry import build_attacks
from agent_sandbox.chaos import ChaosRunner

SHOWCASE = ["env_secret_read", "tcp_egress", "run_as_root", "memory_bomb"]


def main() -> None:
    sandbox = Sandbox()
    docker = sandbox.docker_available()

    print("=" * 72)
    print("1) A normal task: sum the integers on stdin (known answer: 15)")
    print("=" * 72)
    r = sandbox.run(
        code="import sys; print(sum(int(x) for x in sys.stdin.read().split()))",
        profile="hardened" if docker else "subprocess",
        stdin="1 2 3 4 5",
    )
    print(f"profile   : {r.profile}")
    print(f"stdout    : {r.stdout.strip()!r}")
    print(f"exit_code : {r.exit_code}   duration: {r.duration_s:.2f}s")

    print()
    print("=" * 72)
    print("2) Four attacks, outcome decided by the harness (not the attacker)")
    print("=" * 72)
    profiles = ["subprocess"] + (["hardened"] if docker else [])
    runner = ChaosRunner(sandbox, reps=1)
    by_name = {a.name: a for a in build_attacks()}
    try:
        header = f"{'attack':18s} " + " ".join(f"{p:>11s}" for p in profiles)
        print(header)
        print("-" * len(header))
        for name in SHOWCASE:
            attack = by_name[name]
            cells = {p: runner.run_cell(attack, p) for p in profiles}
            row = f"{name:18s} " + " ".join(f"{cells[p].verdict:>11s}" for p in profiles)
            print(row)
        print()
        print("Legend: succeeded = the sandbox did NOT contain it; blocked = it held.")
        if not docker:
            print("(Docker engine not detected -- only the unsafe subprocess baseline was run.)")
        else:
            print("Evidence, hardened profile:")
            for name in SHOWCASE:
                c = runner.run_cell(by_name[name], "hardened")
                print(f"  {name:18s} {c.verdict:10s} {c.evidence}")
    finally:
        runner.close()


if __name__ == "__main__":
    main()
