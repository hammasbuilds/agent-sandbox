"""Harness-side machinery for the chaos suite.

The whole point of this suite is that *the harness* decides whether an attack succeeded,
from evidence it can see for itself -- a connection that actually arrived at a host
listener, a canary token the harness planted and then found in captured output, a marker
file whose mtime moved after the run returned -- never the attacker program's own claim.

``HostBeacon`` is a tiny loopback TCP+UDP listener. A payload that manages real network
egress can reach it and deposit a nonce; the beacon records the nonce, and that recorded
nonce is the objective proof of egress. Under ``--network none`` nothing arrives.
"""

from __future__ import annotations

import contextlib
import socket
import socketserver
import threading
from dataclasses import dataclass, field


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            data = self.request.recv(4096)
        except OSError:
            return
        token = data.decode("utf-8", "ignore").strip()
        # HTTP GETs arrive as "GET /<nonce> HTTP/1.1"; extract the path token too.
        for piece in token.replace("\r", " ").replace("\n", " ").split():
            self.server.hits.add(piece.lstrip("/"))  # type: ignore[attr-defined]
        self.server.hits.add(token)  # type: ignore[attr-defined]
        with contextlib.suppress(OSError):
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.hits: set[str] = set()


class _UDPBeacon(threading.Thread):
    def __init__(self, host: str) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, 0))
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.hits: set[str] = set()
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                data, _ = self.sock.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            self.hits.add(data.decode("utf-8", "ignore").strip())

    def stop(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self.sock.close()


@dataclass
class HostBeacon:
    """Loopback TCP+UDP listener the harness runs while an egress attack executes."""

    bind_host: str = "0.0.0.0"
    tcp_port: int = 0
    udp_port: int = 0
    _tcp: _ThreadingTCPServer | None = field(default=None, repr=False)
    _udp: _UDPBeacon | None = field(default=None, repr=False)
    _tcp_thread: threading.Thread | None = field(default=None, repr=False)

    def start(self) -> HostBeacon:
        self._tcp = _ThreadingTCPServer((self.bind_host, 0), _TCPHandler)
        self.tcp_port = self._tcp.server_address[1]
        self._tcp_thread = threading.Thread(target=self._tcp.serve_forever, daemon=True)
        self._tcp_thread.start()
        self._udp = _UDPBeacon(self.bind_host)
        self.udp_port = self._udp.port
        self._udp.start()
        return self

    @property
    def tcp_hits(self) -> set[str]:
        return self._tcp.hits if self._tcp else set()

    @property
    def udp_hits(self) -> set[str]:
        return self._udp.hits if self._udp else set()

    def stop(self) -> None:
        if self._tcp is not None:
            self._tcp.shutdown()
            self._tcp.server_close()
        if self._udp is not None:
            self._udp.stop()


# Outcome status values.
SUCCEEDED = "succeeded"  # attack achieved its goal -> sandbox did NOT contain it
BLOCKED = "blocked"  # attack contained -> sandbox held
NA = "n/a"  # attack not applicable on this backend/platform
ERROR = "error"  # harness or execution error


@dataclass
class AttackOutcome:
    status: str
    evidence: str


@dataclass
class ChaosContext:
    """Per-run context handed to an attack's check function."""

    nonce: str
    secret: str
    canary_path: str
    canary_token: str
    backend: str
    host_alias: str
    beacon: HostBeacon | None = None
