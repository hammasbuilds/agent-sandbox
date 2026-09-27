from __future__ import annotations

import shutil
import subprocess

import pytest


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and bool(r.stdout.strip())


DOCKER_OK = _docker_available()


def pytest_collection_modifyitems(config, items):
    if DOCKER_OK:
        return
    skip = pytest.mark.skip(reason="Docker engine not available")
    for item in items:
        if "docker" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def docker_ok() -> bool:
    return DOCKER_OK
