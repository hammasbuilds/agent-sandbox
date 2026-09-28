"""Core data types shared by every backend.

These are deliberately backend-agnostic: a ``RunSpec`` describes *what* to run and
under which limits, and a ``RunResult`` captures *what happened*, as observed by the
harness (never as claimed by the code that ran).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, replace
from pathlib import PurePosixPath

# Upper bound on a run's wall-clock budget. The container's keep-alive and the harness's
# own deadlines are derived from it, so an unbounded (or infinite) budget would leave a
# container idling for ever; an hour is far beyond any agent tool call.
MAX_WALL_SECONDS = 3600.0


@dataclass(frozen=True)
class Limits:
    """Resource limits requested for a run.

    A backend maps these onto whatever mechanism it has (cgroups for Docker,
    best-effort ``resource``/timeout for subprocess). ``None`` means "do not set".
    """

    wall_seconds: float = 10.0
    memory_bytes: int | None = None
    cpus: float | None = None
    pids: int | None = None
    nofile: int | None = None
    fsize_bytes: int | None = None
    # Size cap for the writable workspace /work. Set: /work is a tmpfs of this size (inputs
    # copied in, outputs copied out), so a program cannot fill the host disk. None: /work
    # is a host bind mount with no size cap (the Docker baseline).
    workspace_bytes: int | None = None
    # Per stream. Output is read in chunks while the program runs; past this many bytes the
    # program is killed and the result is flagged ``output_truncated``, so the harness never
    # holds more than this in memory whatever the program prints.
    output_bytes: int = 1 << 20

    def __post_init__(self) -> None:
        # coreutils `timeout 0` means "no timeout", so a zero budget would silently disable
        # the very limit it names. Reject it, and any other non-positive limit, up front.
        if not (math.isfinite(self.wall_seconds) and 0 < self.wall_seconds <= MAX_WALL_SECONDS):
            raise ValueError(
                f"wall_seconds must be a finite number in (0, {MAX_WALL_SECONDS:g}], "
                f"got {self.wall_seconds}"
            )
        for name in ("memory_bytes", "pids", "nofile", "fsize_bytes", "workspace_bytes"):
            v = getattr(self, name)
            if v is not None and v <= 0:
                raise ValueError(f"{name} must be > 0 or None, got {v}")
        if self.cpus is not None and not (math.isfinite(self.cpus) and self.cpus > 0):
            raise ValueError(f"cpus must be > 0 or None, got {self.cpus}")
        if self.output_bytes <= 0:
            raise ValueError(f"output_bytes must be > 0, got {self.output_bytes}")

    def with_(self, **changes: object) -> Limits:
        return replace(self, **changes)  # type: ignore[arg-type]


@dataclass(frozen=True)
class RunSpec:
    """A unit of work: source code (or an argv) plus its inputs and limits."""

    code: str | None = None
    argv: tuple[str, ...] | None = None
    stdin: str = ""
    env: dict[str, str] = field(default_factory=dict)
    files_in: dict[str, bytes] = field(default_factory=dict)  # path -> content, in workdir
    files_out: tuple[str, ...] = ()  # paths (relative to workdir) to read back after
    limits: Limits = field(default_factory=Limits)

    # Ask the backend to count the processes still alive in the sandbox when the program
    # exits (before teardown). Only the Docker backend can observe this.
    count_lingering: bool = False

    def __post_init__(self) -> None:
        if (self.code is None) == (self.argv is None):
            raise ValueError("exactly one of code or argv must be given")
        for rel in (*self.files_in, *self.files_out):
            check_workdir_path(rel)
        check_files_in_layout(tuple(self.files_in), code_given=self.code is not None)


# The harness writes the program to this workdir file when a run is given source code.
PROGRAM_FILE = "main.py"


def check_workdir_path(rel: str) -> str:
    """Reject a files-in/out path that could leave the workdir; return it unchanged.

    files_in are written to <workdir>/<rel> on the HOST before the run, so a key such as
    "../x", an absolute path or a drive-qualified path would write outside the workdir. A
    path must also be in normal form ("a/b", not "./a", "a//b", "a/" or "."), so that two
    spellings can never name the same file and "." can never name the workdir itself.
    """
    posix = rel.replace("\\", "/")
    p = PurePosixPath(posix)
    if not rel or p.is_absolute() or ".." in p.parts or ":" in rel:
        raise ValueError(f"file path must be relative and inside the workdir: {rel!r}")
    if not p.parts or str(p) != posix:
        raise ValueError(f"file path must name a file in normal form (like 'data/in.txt'): {rel!r}")
    return rel


def check_files_in_layout(names: tuple[str, ...], *, code_given: bool) -> None:
    """Reject input sets that cannot be written as distinct files.

    * two spellings of one file ("a/b" and "a\\b");
    * a name that is also a directory of another input ("a" and "a/b");
    * ``main.py`` when the run is given source code: the harness writes the program there,
      so the input would be silently overwritten.
    """
    norm = {PurePosixPath(n.replace("\\", "/")) for n in names}
    if len(norm) != len(names):
        raise ValueError(f"two inputs name the same file: {sorted(names)}")
    for p in norm:
        for parent in p.parents:
            if parent in norm:
                raise ValueError(
                    f"input {str(parent)!r} is a file, but input {str(p)!r} needs it to be a "
                    "directory"
                )
    if code_given and PurePosixPath(PROGRAM_FILE) in norm:
        raise ValueError(
            f"input {PROGRAM_FILE!r} would be overwritten by the program itself; rename it"
        )


@dataclass
class RunResult:
    """Everything the harness observed about a run.

    Nothing here is taken on trust from the executed program except ``stdout`` /
    ``stderr``, which are treated as raw bytes to be checked, not believed.
    """

    backend: str
    profile: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool
    # From the kernel/Docker (the container's OOMKilled state), never from program output.
    # None means the backend cannot observe it (the subprocess backend).
    out_of_memory: bool | None = False
    output_truncated: bool = False
    files_out: dict[str, bytes] = field(default_factory=dict)
    argv: tuple[str, ...] = ()  # the real command the backend launched
    error: str | None = None  # harness-level failure (e.g. backend unavailable)
    # Seconds from launching the program to its exit, excluding container start-up.
    program_s: float | None = None
    # Processes other than the container's own PID 1 still alive when the program exited
    # (before teardown), counted by the harness. None when not requested or not observable.
    lingering_processes: int | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.exit_code == 0 and not self.timed_out

    def summary(self) -> str:
        bits = [f"exit={self.exit_code}", f"{self.duration_s:.2f}s"]
        if self.timed_out:
            bits.append("TIMED_OUT")
        if self.out_of_memory:
            bits.append("OOM")
        if self.output_truncated:
            bits.append("truncated")
        if self.error:
            bits.append(f"error={self.error}")
        return " ".join(bits)
