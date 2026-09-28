"""Unit tests for the harness-side success checks, driven by fabricated RunResults."""

from __future__ import annotations

import pytest

from agent_sandbox.attacks.harness import BLOCKED, ERROR, NA, SUCCEEDED, ChaosContext, HostBeacon
from agent_sandbox.attacks.registry import (
    DISK_FILL_THRESHOLD_MB,
    _bomb_check,
    _leak_check,
    build_attacks,
    chk_canary,
    chk_caps,
    chk_dns,
    chk_outlives_run,
    chk_output_flood,
    chk_root,
    chk_secret,
    chk_setuid,
    chk_symlink,
    chk_timeout_enforced,
)
from agent_sandbox.runner import limits_for
from agent_sandbox.types import RunResult


def _ctx(**kw) -> ChaosContext:
    base = dict(
        nonce="NONCE123",
        secret="SEKRET",
        canary_token="TOKEN",
        backend="docker",
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
    r = _res("LINKED ../x", files_out={"out.txt": b"...TOKEN..."})
    out = chk_symlink(r, _ctx())
    assert out.status == SUCCEEDED and "host canary" in out.evidence
    # Any bytes at out.txt came through the link (the payload writes only a symlink), so an
    # in-container file handed back is a breach of file-out too, canary or not.
    other = chk_symlink(_res("LINKED /etc/passwd", files_out={"out.txt": b"root:x:0"}), _ctx())
    assert other.status == SUCCEEDED and "8 bytes" in other.evidence
    assert chk_symlink(_res("LINKED ../x", files_out={}), _ctx()).status == BLOCKED


def test_symlink_check_is_na_when_no_link_could_be_made():
    r = _res("FAIL OSError [WinError 1314] A required privilege is not held", files_out={})
    assert chk_symlink(r, _ctx(backend="subprocess")).status == NA


def test_setuid_check_does_not_count_root_to_root_as_a_gain():
    # Already uid 0: setuid(0) succeeding proves nothing.
    assert chk_setuid(_res("START_UID 0\nESCALATED from 0 to 0"), _ctx()).status == NA
    assert chk_setuid(_res("START_UID 1000\nESCALATED from 1000 to 0"), _ctx()).status == SUCCEEDED
    refused = chk_setuid(_res("START_UID 65534\nFAIL PermissionError from uid 65534"), _ctx())
    assert refused.status == BLOCKED
    assert chk_setuid(_res("Traceback"), _ctx()).status == ERROR
    assert chk_setuid(_res("NOTLINUX"), _ctx(backend="subprocess")).status == NA


def test_dns_check():
    assert chk_dns(_res("RESOLVED 140.82.112.6"), _ctx()).status == SUCCEEDED
    failed = chk_dns(_res("FAIL gaierror [Errno -3] Temporary failure"), _ctx())
    assert failed.status == BLOCKED and "gaierror" in failed.evidence


@pytest.mark.parametrize(
    ("attack", "hit", "miss"),
    [
        ("kernel_version_leak", "KERNEL Linux version 6.6", "FAIL PermissionError"),
        ("mountinfo_leak", "OVERLAY\n...", "CGROUP\n..."),
        ("sysrq_trigger", "SYSRQ_WROTE", "FAIL OSError [Errno 30] Read-only file system"),
        ("kcore_read", "KCORE 64", "MASKED (0 bytes)"),
        ("dev_mem", "DEVMEM_OK", "FAIL FileNotFoundError"),
        ("docker_socket", "DOCKERSOCK b'HTTP/1.0 200'", "FAIL absent"),
        ("cgroupfs_write", "CGROUPFS_WRITABLE", "FAIL OSError [Errno 30]"),
    ],
)
def test_leak_checks_from_the_registry(attack, hit, miss):
    check = {a.name: a for a in build_attacks()}[attack].check
    assert check(_res(hit), _ctx()).status == SUCCEEDED
    assert check(_res(miss), _ctx()).status == BLOCKED
    assert check(_res("NOTLINUX"), _ctx(backend="subprocess")).status == NA


def test_leak_check_notlinux_only_counts_for_subprocess():
    check = _leak_check("KERNEL", "leak")
    # A container is Linux: a NOTLINUX line there is not a reason to call it n/a.
    assert check(_res("NOTLINUX"), _ctx(backend="docker")).status == BLOCKED


def test_disk_fill_threshold_is_above_the_hardened_workspace_cap():
    cap_mb = limits_for("hardened").workspace_bytes // (1 << 20)
    assert cap_mb < DISK_FILL_THRESHOLD_MB
    disk = {a.name: a for a in build_attacks()}["disk_fill"].check
    stopped = disk(_res("STOP ENOSPC OSError\nWROTE_MB 31"), _ctx())
    assert stopped.status == BLOCKED and "ENOSPC" in stopped.evidence
    assert disk(_res("WROTE_MB 48"), _ctx()).status == SUCCEEDED


def test_bomb_check_missing_count_is_an_error_not_a_block():
    assert _bomb_check("THREADS", 128, "t")(_res(""), _ctx()).status == ERROR


def test_outlives_run_attacks_are_resolved_by_the_runner_only():
    assert chk_outlives_run(_res("ORPHAN_PID 1"), _ctx()).status == ERROR
    by = {a.name: a for a in build_attacks()}
    assert by["time_bomb"].outlives_run and by["orphan_survivor"].outlives_run


def test_every_attack_declares_what_its_evidence_rests_on():
    kinds = {a.name: a.evidence for a in build_attacks()}
    assert set(kinds.values()) <= {"observed", "token", "payload"}
    assert kinds["tcp_egress"] == "observed"
    assert kinds["env_secret_read"] == "token"
    assert kinds["run_as_root"] == "payload"


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
