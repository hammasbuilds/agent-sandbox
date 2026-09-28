"""Helpers shared by both backends: bounded output capture and the symlink-safe file reader."""

from __future__ import annotations

import contextlib
import os
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

_CHUNK = 64 * 1024
_POLL_S = 0.02
TRUNCATION_MARK = "\n...[truncated]"
# After the harness asks for a kill, how long to wait for the launched process to go away
# before killing that process directly (the last resort for a stuck `docker` client).
_KILL_WAIT_S = 15.0

KillFn = Callable[["subprocess.Popen[bytes]"], None]


@dataclass
class Captured:
    """What ``run_capped`` observed about one launched process."""

    exit_code: int | None
    stdout: str
    stderr: str
    output_truncated: bool  # a stream went past the cap, so the process was killed
    deadline_hit: bool  # the harness-side deadline fired, so the process was killed
    seconds: float


class _Pump(threading.Thread):
    """Read one pipe in chunks, keeping at most ``cap`` bytes; flag and keep draining past it."""

    def __init__(self, stream: IO[bytes], cap: int, overflow: threading.Event) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._cap = cap
        self._overflow = overflow
        self._lock = threading.Lock()
        self.buf = bytearray()
        self.truncated = False

    def run(self) -> None:
        read = getattr(self._stream, "read1", self._stream.read)
        with contextlib.suppress(OSError, ValueError):
            while chunk := read(_CHUNK):
                with self._lock:
                    room = self._cap - len(self.buf)
                    if room > 0:
                        self.buf += chunk[:room]
                    if len(chunk) > room:
                        self.truncated = True
                        self._overflow.set()

    def text(self) -> str:
        with self._lock:
            out = bytes(self.buf).decode("utf-8", "replace")
            return out + TRUNCATION_MARK if self.truncated else out


def _feed(stream: IO[bytes], data: bytes) -> None:
    with contextlib.suppress(OSError, ValueError):
        if data:
            stream.write(data)
    with contextlib.suppress(OSError, ValueError):
        stream.close()


def run_capped(
    argv: list[str],
    *,
    stdin: bytes,
    output_bytes: int,
    deadline_s: float,
    kill: KillFn,
    **popen_kwargs: Any,
) -> Captured:
    """Run ``argv``, streaming stdout/stderr with a per-stream byte cap.

    The harness never buffers more than ``output_bytes`` per stream: past the cap the rest
    is read and discarded, and ``kill`` is called so a program cannot keep the harness busy
    by printing forever. ``kill`` is also called when ``deadline_s`` passes and on *any*
    exception in the caller's thread (including KeyboardInterrupt) before it propagates.
    """
    start = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **popen_kwargs,
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    overflow = threading.Event()
    pumps = (_Pump(proc.stdout, output_bytes, overflow), _Pump(proc.stderr, output_bytes, overflow))
    feeder = threading.Thread(target=_feed, args=(proc.stdin, stdin), daemon=True)
    for t in (*pumps, feeder):
        t.start()

    deadline_hit = False
    killed_at: float | None = None
    try:
        while True:
            try:
                proc.wait(timeout=_POLL_S)
                break
            except subprocess.TimeoutExpired:
                pass
            now = time.monotonic()
            if killed_at is None and (overflow.is_set() or now - start >= deadline_s):
                deadline_hit = not overflow.is_set()
                kill(proc)
                killed_at = now
            elif killed_at is not None and now - killed_at > _KILL_WAIT_S:
                proc.kill()  # the process we launched ourselves, by handle
                proc.wait()
                break
    except BaseException:
        with contextlib.suppress(Exception):
            kill(proc)
        with contextlib.suppress(Exception):
            proc.kill()
        raise
    seconds = time.monotonic() - start
    for t in pumps:
        t.join(timeout=5)
    return Captured(
        exit_code=proc.returncode,
        stdout=pumps[0].text(),
        stderr=pumps[1].text(),
        output_truncated=pumps[0].truncated or pumps[1].truncated,
        deadline_hit=deadline_hit,
        seconds=seconds,
    )


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
