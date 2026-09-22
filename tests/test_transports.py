"""Actual sockets and subprocess pipes; every failure has a bounded test wait."""

import json
import os
import queue
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum_memory.client import DaemonClient
from continuum_memory.errors import MemoryError
from continuum_memory.security import MAX_FRAME_BYTES, canonical_json
from continuum_memory.storage import paths
from fixtures.harness import EphemeralHarness

ROOT = Path(__file__).resolve().parents[1]
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "transport-fixture"}}}
PING = {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}}
META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "transport-fixture"}}


def wire(value):
    return (canonical_json(value) + "\n").encode("utf-8")


class Bridge:
    def __init__(self, command=None, read_output=True):
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT)]),
                           PYTHONPYCACHEPREFIX=str(ROOT / "work" / "pycache"))
        # This no-vault process exercises the production framing/dispatch loop on
        # platforms without AF_UNIX too. Any unexpected client call fails loudly.
        program = ("import sys; from continuum_memory.mcp import McpServer, serve_stdio; "
                   "raise SystemExit(serve_stdio(McpServer(None), sys.stdin.fileno(), sys.stdout.fileno()))")
        self.process = subprocess.Popen(command or [sys.executable, "-c", program], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, bufsize=0)
        self.lines = queue.Queue()
        if read_output:
            self.reader = threading.Thread(target=self._read, daemon=True)
            self.reader.start()

    def _read(self):
        while True:
            raw = self.process.stdout.readline(MAX_FRAME_BYTES + 1)
            self.lines.put(raw)
            if not raw:
                return

    def send(self, value):
        self.send_raw(wire(value))

    def send_raw(self, raw):
        # Writes may be partial with unbuffered pipes.
        view = memoryview(raw)
        while view:
            sent = self.process.stdin.write(view)
            view = view[sent:]

    def receive(self, timeout=4):
        raw = self.lines.get(timeout=timeout)
        if not raw:
            raise AssertionError("bridge exited without response")
        assert len(raw) <= MAX_FRAME_BYTES
        return json.loads(raw)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=4)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


class McpPipeTests(unittest.TestCase):
    def setUp(self):
        self.bridge = Bridge()
        self.addCleanup(self.bridge.close)

    def initialize(self):
        self.bridge.send(INIT)
        self.assertIn("result", self.bridge.receive())

    def healthy(self):
        self.bridge.send(PING)
        self.assertEqual(self.bridge.receive(), {"jsonrpc": "2.0", "id": 2, "result": {}})

    def test_invalid_tool_names_do_not_crash_or_dispatch(self):
        self.initialize()
        for name in ([], {}, None, 7, True, "unknown"):
            with self.subTest(name=name):
                self.bridge.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                  "params": {"name": name, "arguments": {}}})
                self.assertEqual(self.bridge.receive()["error"]["code"], -32602)
                self.healthy()

    def test_invalid_envelopes_and_params_recover_without_echo(self):
        self.initialize()
        invalid = [None, [], 1, {"jsonrpc": "1.0", "id": 4, "method": "ping"},
                   {"jsonrpc": "2.0", "id": 4, "method": []},
                   {"jsonrpc": "2.0", "id": 4},
                   dict(PING, **{"private-sentinel": "private-sentinel"})]
        invalid += [dict(PING, id=value) for value in ([], {}, None, True, 1.5, 2**64, "x" * 129, "\ud800")]
        for request in invalid:
            with self.subTest(request=repr(request)[:100]):
                self.bridge.send_raw((json.dumps(request) + "\n").encode())
                response = self.bridge.receive()
                self.assertEqual(response["error"]["code"], -32600)
                self.assertNotIn("private-sentinel", json.dumps(response))
                self.healthy()
        for value in ([], None, 1, "private-sentinel"):
            self.bridge.send(dict(PING, params=value))
            self.assertEqual(self.bridge.receive()["error"]["code"], -32602)
            self.healthy()
        self.bridge.send({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "memory_status", "arguments": {"private-sentinel": "private-sentinel"}}})
        response = self.bridge.receive()
        self.assertEqual(response["error"]["code"], -32602)
        self.assertNotIn("private-sentinel", json.dumps(response))

    def test_protocol_validation_and_notifications(self):
        for version in ([], {}, None, 1, "wrong"):
            request = dict(INIT, params=dict(INIT["params"], protocolVersion=version))
            self.bridge.send(request)
            self.assertEqual(self.bridge.receive()["error"]["code"], -32602)
        self.bridge.send({"jsonrpc": "2.0", "id": 10, "method": "server/discover", "params": {"_meta": META}})
        self.assertEqual(self.bridge.receive()["result"]["protocolVersion"], "2026-07-28")
        self.initialize()
        self.bridge.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.bridge.send({"jsonrpc": "2.0", "method": "tools/call", "params": {
            "name": "memory_propose", "arguments": {}}})
        self.healthy()  # No response and no dispatch for either notification.
        for request_id in (0, "", "x" * 128, -(2**63), 2**63 - 1):
            self.bridge.send(dict(PING, id=request_id))
            self.assertEqual(self.bridge.receive()["id"], request_id)

    def test_complete_bad_json_and_utf8_resynchronize(self):
        self.initialize()
        for raw in (b"{bad}\n", b"\xff\n", b'{"id":NaN}\n', b'{"id":1,"id":2}\n',
                    b"[" * 1500 + b"]" * 1500 + b"\n"):
            self.bridge.send_raw(raw + wire(PING))
            self.assertEqual(self.bridge.receive()["error"]["code"], -32700)
            self.assertEqual(self.bridge.receive()["result"], {})

    def test_exact_limit_fragmentation_and_pipelined_frames(self):
        self.initialize()
        raw = wire(dict(PING, id="é" * 64))
        # Split inside a UTF-8 code point, then fill exactly the LF-inclusive cap.
        split = raw.index("é".encode()) + 1
        padded = raw[:-1] + b" " * (MAX_FRAME_BYTES - len(raw)) + b"\n"
        self.bridge.send_raw(padded[:split])
        self.bridge.send_raw(padded[split:] + wire(PING) + wire(PING))
        self.assertEqual(self.bridge.receive()["id"], "é" * 64)
        self.assertEqual(self.bridge.receive()["result"], {})
        self.assertEqual(self.bridge.receive()["result"], {})

    def test_oversize_prefix_fails_before_newline(self):
        self.bridge.send_raw(b"x" * MAX_FRAME_BYTES)
        self.assertEqual(self.bridge.receive()["error"]["message"], "Frame too large")
        self.assertEqual(self.bridge.process.wait(timeout=4), 2)
        self.assertEqual(self.bridge.process.stderr.read(), b"")

    def test_incomplete_frame_and_eof_fail_closed(self):
        self.bridge.send_raw(b'{"id":')
        self.assertEqual(self.bridge.receive()["error"]["message"], "Incomplete frame")
        self.assertEqual(self.bridge.process.wait(timeout=4), 2)
        other = Bridge()
        self.addCleanup(other.close)
        other.send_raw(b"{")
        other.process.stdin.close()
        self.assertEqual(other.receive()["error"]["message"], "Incomplete frame")
        self.assertEqual(other.process.wait(timeout=4), 2)

    def test_trickle_cannot_renew_deadline(self):
        stopped = threading.Event()
        def trickle():
            while not stopped.is_set():
                try:
                    self.bridge.send_raw(b" ")
                except (OSError, ValueError):
                    return
                stopped.wait(0.08)
        sender = threading.Thread(target=trickle, daemon=True)
        started = time.monotonic()
        sender.start()
        try:
            self.assertEqual(self.bridge.receive()["error"]["message"], "Incomplete frame")
            self.assertEqual(self.bridge.process.wait(timeout=4), 2)
            self.assertLess(time.monotonic() - started, 3.5)
        finally:
            stopped.set()
            sender.join(timeout=2)

    def test_idle_and_clean_eof(self):
        # Idle input is allowed; a deadline starts only with a frame's first byte.
        time.sleep(2.1)
        self.initialize()
        self.healthy()
        self.bridge.process.stdin.close()
        self.assertEqual(self.bridge.process.wait(timeout=4), 0)

    def test_stalled_and_disconnected_output_exit_cleanly(self):
        for disconnect in (False, True):
            with self.subTest(disconnect=disconnect):
                other = Bridge(read_output=False)
                self.addCleanup(other.close)
                if disconnect:
                    other.process.stdout.close()
                # Tool-list responses exceed the pipe capacity after a bounded
                # number of requests, even on platforms with larger pipe buffers.
                raw = wire({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": META}})
                def flood():
                    try:
                        for _ in range(512):
                            other.send_raw(raw)
                    except (OSError, ValueError):
                        pass
                sender = threading.Thread(target=flood, daemon=True)
                sender.start()
                self.assertEqual(other.process.wait(timeout=6), 2)
                sender.join(timeout=2)
                self.assertFalse(sender.is_alive())
                self.assertEqual(other.process.stderr.read(), b"")

    def test_oversized_output_is_bounded_and_recovers(self):
        program = ("import sys; from continuum_memory.mcp import McpServer, serve_stdio; "
                   "client=type('FixtureClient', (), {'call':lambda *a: {'payload':'x'*70000}})(); "
                   "raise SystemExit(serve_stdio(McpServer(client),sys.stdin.fileno(),sys.stdout.fileno()))")
        other = Bridge([sys.executable, "-c", program])
        self.addCleanup(other.close)
        other.send(INIT)
        self.assertIn("result", other.receive())
        other.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "memory_status", "arguments": {}}})
        self.assertEqual(other.receive()["error"]["code"], -32000)
        other.send(PING)
        self.assertEqual(other.receive()["result"], {})


@unittest.skipUnless(hasattr(socket, "AF_UNIX") and os.name == "posix", "Unix daemon transport")
class DaemonTransportTests(unittest.TestCase):
    def setUp(self):
        self.harness = EphemeralHarness("fixtures.transport_daemon")
        self.addCleanup(self.harness.close)

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect(str(paths(self.harness.data_dir)["socket"]))
        self.addCleanup(sock.close)
        return sock

    def request(self, method="status", **overrides):
        request = {"id": 1, "method": method, "auth": {"token": self.harness.control.capability["token"]},
                   "params": {"project": self.harness.projects["alpha"]["id"]}}
        request.update(overrides)
        return request

    def response(self, sock):
        raw = bytearray()
        while b"\n" not in raw and len(raw) <= MAX_FRAME_BYTES:
            chunk = sock.recv(8192)
            if not chunk:
                break
            raw.extend(chunk)
        self.assertLessEqual(len(raw), MAX_FRAME_BYTES)
        return json.loads(raw)

    def healthy(self):
        started = time.monotonic()
        value = self.harness.control.call("status", {"project": self.harness.projects["alpha"]["id"]})
        self.assertIsInstance(value, dict)
        self.assertLess(time.monotonic() - started, 0.55)

    def test_incomplete_frame_does_not_block_healthy_client(self):
        bad = self.connect()
        bad.sendall(b'{"id":')
        self.healthy()
        self.assertEqual(bad.recv(1), b"")
        self.healthy()

    def test_trickle_deadline_is_absolute(self):
        bad = self.connect()
        stopped = threading.Event()
        def trickle():
            while not stopped.is_set():
                try:
                    bad.sendall(b" ")
                except OSError:
                    return
                stopped.wait(0.06)
        sender = threading.Thread(target=trickle, daemon=True)
        started = time.monotonic()
        sender.start()
        try:
            self.healthy()
            self.assertEqual(bad.recv(1), b"")
            self.assertLess(time.monotonic() - started, 1.3)
        finally:
            stopped.set()
            sender.join(timeout=2)
        self.healthy()

    def test_admission_saturation_closes_excess_and_recovers(self):
        holders = [self.connect() for _ in range(4)]
        for sock in holders:
            sock.sendall(b"{")
        time.sleep(0.08)
        excess = self.connect()
        self.assertEqual(excess.recv(1), b"")
        for sock in holders:
            self.assertEqual(sock.recv(1), b"")
        self.healthy()

    def test_stalled_readers_and_disconnects_do_not_block_dispatch(self):
        bad = self.connect()
        bad.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        bad.sendall(wire(self.request("fixture_large")))
        self.healthy()
        time.sleep(0.8)
        received = bytearray()
        while True:
            chunk = bad.recv(8192)
            if not chunk:
                break
            received.extend(chunk)
        # Small socket buffers prevent a complete response; EOF before LF proves
        # the write deadline released the blocked writer's slot. Some platforms
        # report no write readiness at all for this receive-buffer size.
        self.assertLess(len(received), 60000)
        self.assertNotIn(b"\n", received)
        self.healthy()
        broken = self.connect()
        broken.sendall(wire(self.request("fixture_large")))
        broken.close()
        self.healthy()

    def test_exact_limit_request_and_fragmented_utf8(self):
        raw = wire(self.request(id="é" * 64))
        split = raw.index("é".encode()) + 1
        padded = raw[:-1] + b" " * (MAX_FRAME_BYTES - len(raw)) + b"\n"
        client = self.connect()
        client.sendall(padded[:split])
        client.sendall(padded[split:])
        self.assertEqual(self.response(client)["id"], "é" * 64)
        self.healthy()

    def test_bad_frames_and_output_size_recover(self):
        for raw, code in ((b"x" * MAX_FRAME_BYTES, "request_too_large"), (b"\xff\n", "invalid_json"),
                          (b"{bad}\n", "invalid_json"), (b'{"id":1,"id":2}\n', "invalid_json"),
                          (b"[" * 1500 + b"]" * 1500 + b"\n", "invalid_json")):
            with self.subTest(code=code):
                bad = self.connect()
                bad.sendall(raw)
                self.assertEqual(self.response(bad)["error"]["code"], code)
                self.healthy()
        large = self.connect()
        large.sendall(wire(self.request("fixture_oversized")))
        self.assertEqual(self.response(large)["error"]["code"], "response_too_large")
        self.healthy()

    def test_invalid_envelopes_auth_and_real_mcp_recovery(self):
        def mutation_counts():
            connection = sqlite3.connect("file:" + str(paths(self.harness.data_dir)["db"]) + "?mode=ro", uri=True)
            try:
                return connection.execute("SELECT (SELECT COUNT(*) FROM proposals), "
                                          "(SELECT COUNT(*) FROM assertion_versions), "
                                          "(SELECT COUNT(*) FROM admin_challenges), "
                                          "(SELECT COUNT(*) FROM audit_events)").fetchone()
            finally:
                connection.close()
        before = mutation_counts()
        for update in ({"id": []}, {"id": None}, {"id": True}, {"id": "x" * 129}, {"params": []},
                       {"method": []}, {"auth": {"token": "invalid"}}, {"private-sentinel": "private-sentinel"}):
            bad = self.connect()
            bad.sendall(wire(self.request(**update)))
            response = self.response(bad)
            self.assertIn("error", response)
            self.assertNotIn("private-sentinel", json.dumps(response))
            self.healthy()
        capability = self.harness.projects["alpha"]["capabilities"]["codex"]
        bridge = Bridge([sys.executable, "-m", "continuum_memory.mcp", "--data-dir", str(self.harness.data_dir),
                         "--capability-file", capability])
        self.addCleanup(bridge.close)
        bridge.send(INIT)
        self.assertIn("result", bridge.receive())
        bridge.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": [], "arguments": {}}})
        self.assertEqual(bridge.receive()["error"]["code"], -32602)
        for name in ("memory_status", "admin_apply"):
            bridge.send({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": name, "arguments": {}}})
            response = bridge.receive()
            if name == "memory_status":
                self.assertIn("structuredContent", response["result"])
            else:
                self.assertEqual(response["error"]["code"], -32602)
        # Scoped credentials still cannot mutate owner-only state through raw I/O.
        scoped = DaemonClient(self.harness.data_dir, Path(capability))
        with self.assertRaises(MemoryError) as caught:
            scoped.call("admin_apply", {})
        self.assertEqual(caught.exception.code, "forbidden")
        proposal = {"subject": "transport sentinel", "claim": "Synthetic transport test claim.",
                    "evidence": "Synthetic transport evidence.", "source_handle": "fixture:transport",
                    "disclosure": ["codex"], "idempotency_key": "transport-sentinel"}
        bridge.send({"jsonrpc": "2.0", "method": "tools/call", "params": {
            "name": "memory_propose", "arguments": proposal}})
        bridge.send({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
            "name": [], "arguments": proposal}})
        self.assertEqual(bridge.receive()["error"]["code"], -32602)
        bridge.send(PING)
        self.assertEqual(bridge.receive()["result"], {})
        self.assertEqual(mutation_counts(), before)


@unittest.skipUnless(hasattr(socket, "AF_UNIX") and os.name == "posix", "Unix daemon client")
class DaemonClientTransportTests(unittest.TestCase):
    def setUp(self):
        self.harness = EphemeralHarness()
        self.addCleanup(self.harness.close)

    def fake_response(self, payload, trickle=False):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        path = self.harness.data_dir / "fixture-reply.sock"
        listener.bind(str(path))
        os.chmod(str(path), 0o600)
        listener.listen(1)
        listener.settimeout(2)
        errors = []
        def reply():
            try:
                with listener.accept()[0] as peer:
                    peer.settimeout(2)
                    peer.recv(MAX_FRAME_BYTES)
                    if trickle:
                        for _ in range(40):
                            peer.sendall(b" ")
                            time.sleep(0.04)
                    else:
                        peer.sendall(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as exc:
                errors.append(exc)
        server = threading.Thread(target=reply, daemon=True)
        client = DaemonClient(self.harness.data_dir, paths(self.harness.data_dir)["control"])
        client.socket_path = path
        server.start()
        started = time.monotonic()
        try:
            with patch("continuum_memory.client.CLIENT_TIMEOUT", 0.4):
                with self.assertRaises(MemoryError) as caught:
                    client.call("status", {})
            self.assertLess(time.monotonic() - started, 1.3)
            return caught.exception.code
        finally:
            server.join(timeout=2)
            listener.close()
            path.unlink()
            self.assertFalse(server.is_alive())
            self.assertEqual(errors, [])

    def test_client_rejects_malformed_response_envelopes(self):
        for raw in (b"[]\n", b"null\n", b"{}\n", b"\xff\n", b'{"id":1,"result":0}',
                    wire({"id": True, "result": {}}), wire({"id": 2, "result": {}}),
                    wire({"id": 1, "result": {}, "error": {}}), wire({"id": 1, "error": []}),
                    wire({"id": 1, "error": {"code": [], "message": "bad"}}),
                    b"x" * MAX_FRAME_BYTES):
            with self.subTest(raw=raw[:60]):
                self.assertEqual(self.fake_response(raw), "invalid_response")

    def test_client_response_trickle_cannot_renew_deadline(self):
        self.assertEqual(self.fake_response(b"", trickle=True), "unavailable")


if __name__ == "__main__":
    unittest.main()
