"""Ablation: is `symlink_fileout` blocked by the harness's guard, or by something else?

Runs the symlink attack under every profile twice: once with the real symlink-safe
`read_files_out`, once with a naive reader that follows whatever is at the output path.
For each run it records whether the payload actually managed to create the symlink
(LINKED vs FAIL) -- a "blocked" verdict only means the guard worked if a link existed to
be refused. Writes results/symlink_ablation.json.

Run:  uv run python scripts/symlink_ablation.py
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from agent_sandbox import Sandbox
from agent_sandbox.attacks.registry import build_attacks
from agent_sandbox.backends import docker as docker_mod
from agent_sandbox.backends import subprocess_backend as sub_mod
from agent_sandbox.chaos import ChaosRunner


def naive_read(workdir: Path, names: tuple[str, ...]) -> dict[str, bytes]:
    """What a harness without the guard does: open the path and follow links."""
    out: dict[str, bytes] = {}
    for rel in names:
        try:
            out[rel] = (workdir / rel).read_bytes()
        except OSError:
            continue
    return out


LINUX_PROBE = r"""
import json, os, sys
sys.path.insert(0, "/src")
from pathlib import Path
from agent_sandbox.backends.base import read_files_out
root = Path("/probe"); work = root / "work"; work.mkdir(parents=True, exist_ok=True)
(root / "canary.txt").write_text("LINUXCANARY-7f3a")
link = work / "out.txt"
if link.is_symlink() or link.exists():
    link.unlink()
os.symlink("../canary.txt", link)          # the attack: relative link out of the workdir
naive = link.read_bytes().decode()          # a reader that just opens the path
guarded = read_files_out(work, ("out.txt",))
guarded_text = {k: v.decode() for k, v in guarded.items()}
print(json.dumps({"naive_read": naive, "guarded_read": guarded_text}))
"""


def linux_host_simulation() -> dict:
    """Run the harness-side read on Linux (inside a container), where bind-mount symlinks
    are real -- the conditions a Linux Docker host would give the harness."""
    import subprocess
    import tempfile

    src = Path(__file__).resolve().parents[1] / "src"
    with tempfile.TemporaryDirectory(prefix="agsbx-linkprobe-") as probe:
        r = subprocess.run(
            [
                "docker", "run", "--rm", "--label", "agent-sandbox=1",
                "-v", f"{src}:/src:ro", "-v", f"{probe}:/probe",
                "python:3.12-slim", "python", "-c", LINUX_PROBE,
            ],
            capture_output=True, text=True, timeout=300,
        )
    if r.returncode != 0:
        return {"error": r.stderr.strip()[-300:]}
    data = json.loads(r.stdout.strip().splitlines()[-1])
    data["naive_leaked_canary"] = "LINUXCANARY" in data["naive_read"]
    data["guard_leaked_canary"] = any("LINUXCANARY" in v for v in data["guarded_read"].values())
    return data


def main() -> None:
    sandbox = Sandbox()
    profiles = ["subprocess"] + (["default", "hardened"] if sandbox.docker_available() else [])
    attack = next(a for a in build_attacks() if a.name == "symlink_fileout")
    guarded = (docker_mod.read_files_out, sub_mod.read_files_out)
    rows = []
    runner = ChaosRunner(sandbox, reps=1)
    try:
        for reader_name in ("guarded", "naive"):
            reader = guarded[0] if reader_name == "guarded" else naive_read
            docker_mod.read_files_out = reader
            sub_mod.read_files_out = reader
            for p in profiles:
                outcome, result = runner._run_once(attack, p)
                rows.append(
                    {
                        "reader": reader_name,
                        "profile": p,
                        "link_created": "LINKED" in result.stdout,
                        "payload_said": result.stdout.strip()[:120],
                        "verdict": outcome.status,
                        "evidence": outcome.evidence,
                    }
                )
    finally:
        docker_mod.read_files_out, sub_mod.read_files_out = guarded
        runner.close()

    linux = linux_host_simulation() if sandbox.docker_available() else None
    report = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "windows_host_runs": rows,
        "linux_host_simulation": linux,
    }
    out = Path("results/symlink_ablation.json")
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    for r in rows:
        print(f"  {r['reader']:8s} {r['profile']:11s} link={r['link_created']!s:5s} "
              f"{r['verdict']:10s} | {r['payload_said'][:70]}")
    print("  linux-host simulation:", linux)


if __name__ == "__main__":
    main()
