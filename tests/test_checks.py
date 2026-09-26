"""Unit tests for the harness-side success checks, driven by fabricated RunResults."""

from __future__ import annotations

from agent_sandbox.attacks.harness import BLOCKED, NA, SUCCEEDED, ChaosContext, HostBeacon
from agent_sandbox.attacks.registry import (
    _bomb_check,
    chk_canary,
    chk_caps,
    chk_output_flood,
    chk_root,
    chk_secret,
    chk_symlink,
    chk_timeout_enforced,
)
from agent_sandbox.types import RunResult


def _ctx(**kw) -> ChaosContext:
    base = dict(
        nonce="NONCE123",
        secret="SEKRET",
        canary_path="/x",
        canary_token="TOKEN",
        backend="docker",
        host_alias="host.docker.internal",
        beacon=None,
    )
    base.update(kw)
    return ChaosContext(**base)


def _res(stdout="", **kw) -> RunResult:
    base = dict(
        backend="docker",
        profile="hardened",
        exit_code=0,
        stdout=stdout,
        stderr="",
        duration_s=0.1,
        timed_out=False,
    )
    base.update(kw)
    return RunResult(**base)


def test_secret_check():
    assert chk_secret(_res("SECRET SEKRET"), _ctx()).status == SUCCEEDED
    assert chk_secret(_res("NOSECRET"), _ctx()).status == BLOCKED


def test_canary_check():
    assert chk_canary(_res("CANARY TOKEN"), _ctx()).status == SUCCEEDED
    assert chk_canary(_res("FAIL FileNotFound"), _ctx()).status == BLOCKED


def test_root_check_and_na():
    assert chk_root(_res("UID 0"), _ctx()).status == SUCCEEDED
    assert chk_root(_res("UID 65534"), _ctx()).status == BLOCKED
    # Windows-host subprocess: payload prints NOTLINUX -> not applicable
    assert chk_root(_res("NOTLINUX"), _ctx(backend="subprocess")).status == NA


def test_caps_check_parses_hex():
    assert chk_caps(_res("CAPEFF 0xa80425fb"), _ctx()).status == SUCCEEDED
    assert chk_caps(_res("CAPEFF 0x0"), _ctx()).status == BLOCKED


def test_bomb_check_threshold_and_oom():
    check = _bomb_check("ALLOC_MB", 200, "memory")
    assert check(_res("ALLOC_MB 300"), _ctx()).status == SUCCEEDED
    assert check(_res("ALLOC_MB 40"), _ctx()).status == BLOCKED
    assert check(_res("ALLOC_MB 0", out_of_memory=True), _ctx()).status == BLOCKED


def test_timeout_enforced_is_blocked_when_killed():
    assert chk_timeout_enforced(_res(timed_out=True, duration_s=10.0), _ctx()).status == BLOCKED
    assert chk_timeout_enforced(_res("done", timed_out=False), _ctx()).status == SUCCEEDED


def test_output_flood_blocked_when_truncated():
    assert chk_output_flood(_res(output_truncated=True), _ctx()).status == BLOCKED
    assert chk_output_flood(_res("DONE"), _ctx()).status == SUCCEEDED


def test_symlink_check_uses_fileout():
    r = _res(files_out={"out.txt": b"...TOKEN..."})
    assert chk_symlink(r, _ctx()).status == SUCCEEDED
    r2 = _res(files_out={})
    assert chk_symlink(r2, _ctx()).status == BLOCKED


def test_beacon_records_loopback_egress():
    beacon = HostBeacon().start()
    try:
        import socket

        s = socket.create_connection(("127.0.0.1", beacon.tcp_port), timeout=3)
        s.sendall(b"NONCE123")
        s.recv(16)
        s.close()
        import time

        time.sleep(0.3)
        assert "NONCE123" in beacon.tcp_hits
    finally:
        beacon.stop()
