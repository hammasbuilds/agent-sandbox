"""agent-sandbox: run AI-generated code under named hardening profiles, and measure
what each profile actually stops.
"""

from __future__ import annotations

from .profiles import (
    DOCKER_BASELINE,
    HARDENED,
    PROFILES,
    SUBPROCESS,
    Profile,
    get_profile,
)
from .runner import Sandbox, enforced_limits, limits_for
from .types import Limits, RunResult, RunSpec

__all__ = [
    "Sandbox",
    "RunSpec",
    "RunResult",
    "Limits",
    "Profile",
    "PROFILES",
    "DOCKER_BASELINE",
    "HARDENED",
    "SUBPROCESS",
    "get_profile",
    "limits_for",
    "enforced_limits",
]

__version__ = "0.1.0"
