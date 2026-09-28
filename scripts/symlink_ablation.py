"""Ablation: is `symlink_fileout` blocked by the harness's guard, or by something else?

Runs the symlink attack under every profile twice: once with the real file-out readers,
once with naive ones that follow whatever is at the output path. There are two real
readers: `read_files_out` on the host (subprocess, and docker-baseline's bind-mounted
/work) and the in-container `tar` copy-out (hardened's tmpfs /work); the naive stand-ins
are a plain `read_bytes()` and `docker exec cat`. For each run it records whether the
payload actually managed to create the symlink (LINKED vs FAIL): a "blocked" verdict only
means a guard worked if a link existed to be refused.

Run:  uv run python scripts/symlink_ablation.py --out results/symlink_ablation.json --force
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import uuid
from pathlib import Path

from agent_sandbox import Sandbox
from agent_sandbox.attacks.registry import build_attacks
from agent_sandbox.backends import docker as docker_mod
from agent_sandbox.backends import subprocess_backend as sub_mod
from agent_sandbox.chaos import ChaosRunner

SESSION = "symlink-ablation-" + uuid.uuid4().hex[:8]
DEFAULT_OUT = "results/symlink_ablation.json"


def naive_read(workdir: Path, names: tuple[str, ...]) -> dict[str, bytes]:
    """What a host-side reader without the guard does: open the path and follow links."""
    out: dict[str, bytes] = {}
    for rel in names:
        try:
            out[rel] = (workdir / rel).read_bytes()
        except OSError:
            continue
    return out


def naive_copy_out(self, name: str, names: tuple[str, ...]) -> dict[str, bytes]:
    """What an in-container copy-out without the tar filter does: `cat` follows links."""
    out: dict[str, bytes] = {}
    for rel in names:
        r = subprocess.run(
            ["docker", "exec", "--workdir", "/work", name, "cat", "--", rel],
            capture_output=True,
            timeout=60,
        )
        if r.returncode == 0:
            out[rel] = r.stdout
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
                "docker",
                "run",
                "--rm",
                "--label",
                "agent-sandbox=1",
                "--label",
                f"agent-sandbox-session={SESSION}",
                "-v",
                f"{src}:/src:ro",
                "-v",
                f"{probe}:/probe",
                "python:3.12-slim",
                "python",
                "-c",
                LINUX_PROBE,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
    if r.returncode != 0:
        return {"error": r.stderr.strip()[-300:]}
    data = json.loads(r.stdout.strip().splitlines()[-1])
    data["naive_leaked_canary"] = "LINUXCANARY" in data["naive_read"]
    data["guard_leaked_canary"] = any("LINUXCANARY" in v for v in data["guarded_read"].values())
    return data


def main() -> None:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--out", default=None, help=f"output path (default: {DEFAULT_OUT})")
    ap.add_argument("--force", action="store_true", help="overwrite the default output file")
    args = ap.parse_args()
    out = Path(args.out or DEFAULT_OUT)
    if args.out is None and out.exists() and not args.force:
        raise SystemExit(f"{out} already exists; pass --out PATH or --force")

    sandbox = Sandbox(session=SESSION)
    docker = sandbox.docker_available()
    profiles = ["subprocess"] + (["docker-baseline", "hardened"] if docker else [])
    attack = next(a for a in build_attacks() if a.name == "symlink_fileout")
    guarded = (
        docker_mod.read_files_out,
        sub_mod.read_files_out,
        docker_mod.DockerBackend._copy_out,
    )
    rows = []
    runner = ChaosRunner(sandbox, reps=1)
    try:
        for reader_name in ("guarded", "naive"):
            naive = reader_name == "naive"
            docker_mod.read_files_out = naive_read if naive else guarded[0]
            sub_mod.read_files_out = naive_read if naive else guarded[1]
            docker_mod.DockerBackend._copy_out = naive_copy_out if naive else guarded[2]
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
        docker_mod.read_files_out, sub_mod.read_files_out = guarded[0], guarded[1]
        docker_mod.DockerBackend._copy_out = guarded[2]
        runner.close()
        if docker:
            sandbox.cleanup()

    linux = linux_host_simulation() if docker else None
    report = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "windows_host_runs": rows,
        "linux_host_simulation": linux,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    for r in rows:
        print(
            f"  {r['reader']:8s} {r['profile']:15s} link={r['link_created']!s:5s} "
            f"{r['verdict']:10s} | {r['payload_said'][:70]}"
        )
    print("  linux-host simulation:", linux)


if __name__ == "__main__":
    main()
