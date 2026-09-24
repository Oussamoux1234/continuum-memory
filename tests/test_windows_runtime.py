"""Native runtime behavior, not a same-account or human-presence boundary."""

import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from continuum_memory.errors import MemoryError
from continuum_memory.windows_pipe import PipeServer, connect
from continuum_memory.windows_runtime import DRAIN_ACK, PipePool, Request, WindowsMemoryServer, exchange


ROOT = Path(__file__).resolve().parents[1]


class RequestStateTest(unittest.TestCase):
    def test_expired_or_cancelled_request_never_dispatches(self):
        expired = Request(b"{}", time.monotonic() - 1)
        self.assertFalse(expired.claim())
        cancelled = Request(b"{}", time.monotonic() + 1)
        cancelled.cancel()
        self.assertFalse(cancelled.claim())

    def test_reply_is_per_request_and_cancellation_cannot_reassign_it(self):
        old = Request(b"old", time.monotonic() + 1)
        self.assertTrue(old.claim())
        old.cancel()
        newer = Request(b"new", time.monotonic() + 1)
        old.complete(b"old result\n")
        self.assertIsNone(old.reply)
        self.assertIsNone(newer.reply)
        self.assertTrue(newer.claim())
        newer.complete(b"new result\n")
        self.assertEqual(newer.reply, b"new result\n")
        with self.assertRaises(AttributeError):
            newer.raw = b"reassigned"

    def test_drain_ack_failure_does_not_discard_an_obtained_reply(self):
        class Connection:
            def send(self, frame):
                if frame == DRAIN_ACK:
                    raise MemoryError("pipe_timeout", "Injected ACK-only fault")

            def receive(self):
                return b'{"id":1,"result":{}}\n'

        @contextmanager
        def connected(*_args, **_kwargs):
            yield Connection()

        # Deterministic orchestration test, not native timeout evidence.
        with mock.patch("continuum_memory.windows_runtime.connect", connected):
            self.assertEqual(exchange(b"b" * 32, b"{}\n"), b'{"id":1,"result":{}}\n')


@unittest.skipUnless(os.name == "nt", "Native Windows runtime evidence requires Windows")
class NativeRuntimeTest(unittest.TestCase):
    def setUp(self):
        from tests.test_windows_pipe import NativePipeTest
        self.temp = tempfile.TemporaryDirectory(prefix="continuum-pipe-runtime-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binding = secrets.token_bytes(32)
        self.stop_path = self.root / "stop"
        self.stats_path = self.root / "stats.json"
        self.signal = lambda process, value: NativePipeTest.signal(self, process, value)
        self.process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--runtime-child", self.binding.hex(),
             str(self.stop_path), str(self.stats_path)],
            env=dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT)])),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop)
        self.signal(self.process, b"ready")

    def stop(self):
        self.stop_path.touch()
        try:
            self.output, self.errors = self.process.communicate(timeout=7)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.output, self.errors = self.process.communicate(timeout=3)
            self.fail("Runtime did not stop within its bounded worker-drain deadline")

    def test_real_concurrent_clients_dispatch_on_only_the_owner_thread(self):
        clients = [subprocess.Popen(
            [sys.executable, "-c", "from continuum_memory.windows_runtime import exchange; "
             "import sys; print(exchange(bytes.fromhex(sys.argv[1]), b'concurrent\\n').decode().strip())",
             self.binding.hex()], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(os.environ, PYTHONPATH=str(ROOT / "src"))) for _ in range(8)]
        try:
            for client in clients:
                output, error = client.communicate(timeout=7)
                self.assertEqual(client.returncode, 0, error)
                self.assertEqual(output.strip(), b"concurrent")
        finally:
            for client in clients:
                if client.poll() is None:
                    client.kill()
                    client.communicate(timeout=3)
        self.stop()
        stats = json.loads(self.stats_path.read_text())
        self.assertEqual(stats["dispatch_threads"], [stats["owner_thread"]])
        self.assertEqual(stats["active_max"], 1)
        self.assertEqual(stats["workers_after_stop"], 0)
        self.assertEqual(stats["created_workers"], 16)
        self.assertEqual(stats["requests"], 8)

    def test_partial_request_does_not_hold_up_a_healthy_client(self):
        with connect(self.binding) as stalled:
            started = time.monotonic()
            self.assertEqual(exchange(self.binding, b"healthy\n"), b"healthy\n")
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertIsNotNone(stalled.handle)

    def test_response_is_retained_until_the_reader_acknowledges(self):
        with connect(self.binding) as client:
            client.send(b"delayed\n")
            time.sleep(0.2)
            self.assertEqual(client.receive(), b"delayed\n")
            client.send(DRAIN_ACK)
        self.assertEqual(exchange(self.binding, b"next\n"), b"next\n")

    def test_saturation_refuses_excess_and_recovers_without_more_workers(self):
        from concurrent.futures import ThreadPoolExecutor
        ready, release = threading.Barrier(17, timeout=1.5), threading.Event()

        def hold():
            with connect(self.binding):
                ready.wait()
                release.wait(1.5)

        with ThreadPoolExecutor(max_workers=16) as clients:
            futures = [clients.submit(hold) for _ in range(16)]
            try:
                ready.wait()
                with self.assertRaises(MemoryError):
                    exchange(self.binding, b"excess\n")
            finally:
                release.set()
            for future in futures:
                future.result(timeout=3)
        deadline = time.monotonic() + 3
        while True:
            try:
                self.assertEqual(exchange(self.binding, b"recovered\n"), b"recovered\n")
                break
            except MemoryError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)

    def test_second_pool_cannot_adopt_endpoint_and_kill_releases_it(self):
        with self.assertRaises(MemoryError) as caught:
            PipePool(self.binding)
        self.assertEqual(caught.exception.code, "pipe_endpoint_occupied")
        self.process.kill()
        self.process.communicate(timeout=3)
        with PipePool(self.binding):
            pass

    def test_shutdown_cancels_pending_reads_without_worker_leaks(self):
        with connect(self.binding):
            self.stop()
        self.assertEqual(self.process.returncode, 0, self.errors)
        self.assertEqual(json.loads(self.stats_path.read_text())["workers_after_stop"], 0)

    def test_partial_pool_creation_releases_every_created_instance(self):
        binding = secrets.token_bytes(32)
        count = 0

        def factory(*args, **kwargs):
            nonlocal count
            count += 1
            if count == 4:
                raise OSError("Injected fourth-instance startup failure")
            return PipeServer(*args, **kwargs)

        with mock.patch("continuum_memory.windows_runtime.PipeServer", side_effect=factory):
            with self.assertRaises(OSError):
                PipePool(binding)
        with PipePool(binding):
            pass

    def test_partial_and_trickled_frames_do_not_dispatch(self):
        with connect(self.binding) as connection:
            started = time.monotonic()
            while time.monotonic() - started < 3:
                try:
                    connection.api.operation(connection.handle, "write", connection.deadline, data=b"x")
                except MemoryError:
                    break
                time.sleep(0.25)
            with self.assertRaises(MemoryError):
                connection.receive()
            self.assertLess(time.monotonic() - started, 4)
        self.assertEqual(exchange(self.binding, b"healthy\n"), b"healthy\n")
        self.stop()
        self.assertEqual(json.loads(self.stats_path.read_text())["requests"], 1)


@unittest.skipUnless(os.name == "nt", "Native Windows integrated vault evidence requires Windows")
class NativeVaultRuntimeTest(unittest.TestCase):
    def test_real_mcp_cross_provider_lifecycle(self):
        from fixtures.harness import EphemeralHarness
        with EphemeralHarness() as fixture:
            codex, claude = fixture.mcp("alpha", "codex"), fixture.mcp("alpha", "claude")
            proposal = codex.call("memory_propose", {
                "subject": "native handoff", "claim": "Synthetic SQLite decision.",
                "evidence": "Synthetic native fixture.", "source_handle": "fixture:windows",
                "disclosure": ["codex", "claude"], "idempotency_key": "native-handoff-001"})
            result = fixture.approve({"operation": "accept_proposal", "project": fixture.projects["alpha"]["id"],
                                      "proposal_id": proposal["proposal_id"]})["result"]
            found = claude.call("memory_search", {"query": "native handoff"})
            self.assertEqual(found["cards"][0]["version_id"], result["assertion_id"])
            full = claude.call("memory_get", {"recall_id": found["recall_id"], "ids": [result["assertion_id"]]})
            self.assertEqual(full["records"][0]["evidence"]["body"], "Synthetic native fixture.")
            fixture.approve({"operation": "correct", "project": fixture.projects["alpha"]["id"],
                             "target_id": result["assertion_id"], "claim": "Corrected native fixture."})
            fixture.approve({"operation": "forget", "project": fixture.projects["alpha"]["id"],
                             "target_id": result["memory_id"]})
            self.assertEqual(claude.call("memory_search", {"query": "native handoff"})["cards"], [])
            self.assertEqual(fixture.control.call("audit_verify", {})["status"], "valid")

    def test_production_daemon_has_no_prototype_approval_fallback(self):
        from fixtures.harness import EphemeralHarness
        with EphemeralHarness("continuum_memory.daemon") as fixture:
            project = fixture.projects["alpha"]["id"]
            self.assertEqual(fixture.control.call("status", {"project": project})["approval_boundary"],
                             "os_approval_unavailable")
            with self.assertRaises(MemoryError) as caught:
                fixture.control.call("admin_preview", {"project": project, "operation": "remember", "claim": "No fallback"})
            self.assertEqual(caught.exception.code, "approval_broker_unavailable")

    def test_losing_daemon_never_opens_store(self):
        from fixtures.harness import EphemeralHarness
        with EphemeralHarness() as fixture:
            sentinel = fixture.data_dir / "loser-opened-store"
            script = (
                "import sys; from pathlib import Path; from continuum_memory import daemon; "
                "original=daemon.Store\n"
                "def opened(path):\n"
                " Path(sys.argv[2]).touch()\n"
                " return original(path)\n"
                "daemon.Store=opened\n"
                "raise SystemExit(daemon.main(['--data-dir',sys.argv[1]]))\n")
            loser = subprocess.run([sys.executable, "-c", script, str(fixture.data_dir), str(sentinel)],
                env=dict(os.environ, PYTHONPATH=str(ROOT / "src")), capture_output=True, timeout=5)
            self.assertEqual(loser.returncode, 2)
            self.assertIn(b"pipe_endpoint_occupied", loser.stderr)
            self.assertFalse(sentinel.exists())
            self.assertEqual(fixture.control.call("status", {"project": fixture.projects["alpha"]["id"]})["status"], "available")

    def test_native_mcp_and_direct_envelopes_reject_secrets_without_echo_or_mutation(self):
        import sqlite3
        from continuum_memory.security import canonical_json, read_private
        from continuum_memory.storage import load_capability, paths
        from fixtures.harness import EphemeralHarness
        from tests.test_admission import SECRETS
        with EphemeralHarness() as fixture:
            client = fixture.mcp("alpha", "codex")
            secret = SECRETS["github_fine"]  # Synthetic, never a real credential.
            params = {"subject": "Native admission", "claim": secret, "evidence": "Synthetic fixture.",
                      "source_handle": "fixture:native", "disclosure": ["codex"],
                      "idempotency_key": "native-admission-001"}
            response = client.call_raw("memory_propose", params)
            self.assertEqual(response["result"]["structuredContent"]["error"]["code"], "secret_rejected")
            self.assertNotIn(secret, canonical_json(response))
            request = {"jsonrpc": "2.0", "id": secret, "method": "tools/call", "params": {
                "name": "memory_propose", "arguments": dict(params, claim="Harmless claim."),
                "_meta": client._meta()}}
            client.process.stdin.write(canonical_json(request) + "\n")
            client.process.stdin.flush()
            response = json.loads(client.process.stdout.readline())
            self.assertIsNone(response["id"])
            self.assertEqual(response["error"]["code"], -32600)
            self.assertNotIn(secret, canonical_json(response))
            capability = load_capability(Path(fixture.projects["alpha"]["capabilities"]["codex"]))
            binding = read_private(paths(fixture.data_dir)["ipc_binding"], 32)
            for request_id, expected in ((secret, "invalid_request"), (1, "secret_rejected")):
                raw = {"id": request_id, "method": "propose", "auth": {"token": capability["token"]},
                       "params": params}
                response = json.loads(exchange(binding, (canonical_json(raw) + "\n").encode()))
                self.assertEqual(response["error"]["code"], expected)
                self.assertEqual(response["id"], None if request_id == secret else 1)
                self.assertNotIn(secret, canonical_json(response))
            self.assertIn("status", client.call("memory_status", {}))
            client.process.stdin.close()
            self.assertEqual(client.process.wait(timeout=3), 0)
            self.assertEqual(client.process.stderr.read(), "")
            connection = sqlite3.connect(str(fixture.data_dir / "continuum.db"))
            try:
                self.assertEqual(connection.execute("SELECT count(*) FROM proposals").fetchone()[0], 0)
            finally:
                connection.close()
            for path in fixture.data_dir.iterdir():
                if path.is_file():
                    self.assertNotIn(secret.encode(), path.read_bytes(), path.name)


def runtime_child(binding, stop_path, stats_path):
    sys.stdout.reconfigure(newline="\n")
    stats = {"owner_thread": threading.get_ident(), "dispatch_threads": set(),
             "active_max": 0, "requests": 0}
    active = 0

    def handler(raw):
        nonlocal active
        active += 1
        try:
            stats["active_max"] = max(active, stats["active_max"])
            stats["dispatch_threads"].add(threading.get_ident())
            stats["requests"] += 1
            return raw + b"\n"
        finally:
            active -= 1

    with PipePool(binding) as pool:
        server = WindowsMemoryServer(pool, handler)
        print("ready", flush=True)
        try:
            server.serve_forever(stop_requested=lambda: stop_path.exists())
        finally:
            server.server_close()
        stats["workers_after_stop"] = sum(worker.thread.is_alive() for worker in pool.workers)
        stats["created_workers"] = len(pool.workers)
    stats["dispatch_threads"] = sorted(stats["dispatch_threads"])
    stats_path.write_text(json.dumps(stats))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--runtime-child":
        runtime_child(bytes.fromhex(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
    else:
        unittest.main()
