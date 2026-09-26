"""agent-sandbox: run AI-generated code under named hardening profiles, and measure
what each profile actually stops.
"""

from __future__ import annotations

from .profiles import DEFAULT, HARDENED, PROFILES, SUBPROCESS, Profile, get_profile
from .runner import Sandbox, limits_for
from .types import Limits, RunResult, RunSpec

__all__ = [
    "Sandbox",
    "RunSpec",
    "RunResult",
    "Limits",
    "Profile",
    "PROFILES",
    "DEFAULT",
    "HARDENED",
    "SUBPROCESS",
    "get_profile",
    "limits_for",
]

__version__ = "0.1.0"
