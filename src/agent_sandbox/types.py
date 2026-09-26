"""Core data types shared by every backend.

These are deliberately backend-agnostic: a ``RunSpec`` describes *what* to run and
under which limits, and a ``RunResult`` captures *what happened*, as observed by the
harness (never as claimed by the code that ran).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path


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
    output_bytes: int = 1 << 20  # captured stdout/stderr are truncated past this

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

    def __post_init__(self) -> None:
        if (self.code is None) == (self.argv is None):
            raise ValueError("exactly one of code or argv must be given")


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
    out_of_memory: bool = False
    output_truncated: bool = False
    files_out: dict[str, bytes] = field(default_factory=dict)
    argv: tuple[str, ...] = ()  # the real command the backend launched
    error: str | None = None  # harness-level failure (e.g. backend unavailable)

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


def ensure_workdir(path: str | Path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p
