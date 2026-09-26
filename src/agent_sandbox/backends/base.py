"""Backend protocol and shared helpers."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from ..profiles import Profile
from ..types import RunResult, RunSpec


class Backend(Protocol):
    name: str

    def available(self) -> bool:
        """Cheap check that this backend can actually run (engine present, etc.)."""
        ...

    def run(self, spec: RunSpec, profile: Profile) -> RunResult:
        """Execute ``spec`` under ``profile`` and return what the harness observed."""
        ...


def truncate(text: str, limit: int) -> tuple[str, bool]:
    """Truncate captured output to ``limit`` bytes (utf-8), flagging if we cut it."""
    raw = text.encode("utf-8", "replace")
    if len(raw) <= limit:
        return text, False
    return raw[:limit].decode("utf-8", "ignore") + "\n...[truncated]", True


def read_files_out(workdir: Path, names: tuple[str, ...]) -> dict[str, bytes]:
    """Read requested output files, refusing to follow symlinks out of the workdir.

    A malicious program can plant a symlink at an output path aimed at a host file; a
    naive reader would follow it and hand the caller data it never should have seen. We
    only read a real regular file whose resolved path stays inside the workdir.
    """
    root = workdir.resolve()
    out: dict[str, bytes] = {}
    for rel in names:
        candidate = workdir / rel
        try:
            if candidate.is_symlink() or not candidate.exists():
                continue
            real = candidate.resolve()
            if os.path.commonpath([root, real]) != str(root):
                continue
            if not real.is_file():
                continue
            out[rel] = real.read_bytes()
        except OSError:
            continue
    return out
