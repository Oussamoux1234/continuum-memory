"""Real subprocess readiness and cleanup for the disposable MCP harness."""

import json
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum_memory.security import MAX_FRAME_BYTES
from fixtures.harness import EphemeralHarness, McpFixtureClient


READY = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "2026-07-28",
        "serverInfo": {"name": "continuum-memory", "version": "fixture"},
    },
}
WORKER_NAME = "continuum-mcp-fixture-ready"


class FixtureStartupTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-mcp-startup-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.processes = []
        self.real_popen = subprocess.Popen
        self.addCleanup(self.cleanup_processes)

    def cleanup_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except BrokenPipeError:
                        pass

    def child(self, source, extra_arguments=()):
        # Only substitute the executable body; keep the harness's real pipe,
        # buffering, environment, reader, timeout and cleanup behavior.
        def launch(command, **kwargs):
            process = self.real_popen(
                [command[0], "-u", "-c", source, *extra_arguments], **kwargs
            )
            self.processes.append(process)
            return process
        return patch("fixtures.harness.subprocess.Popen", side_effect=launch)

    def assert_reaped_and_closed(self, process):
        self.assertIsNotNone(process.poll())
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def assert_readiness_failure(self, source, timeout=1.0):
        workers_before = {thread for thread in threading.enumerate() if thread.name == WORKER_NAME}
        started = time.monotonic()
        with self.child(source), patch("fixtures.harness.MCP_STARTUP_TIMEOUT", timeout):
            with self.assertRaisesRegex(RuntimeError, "^MCP fixture did not become ready$") as caught:
                McpFixtureClient(self.directory, self.directory / "unused.cap", "startup-fixture")
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertLess(time.monotonic() - started, timeout + 3)
        self.assert_reaped_and_closed(self.processes[-1])
        workers_after = {thread for thread in threading.enumerate() if thread.name == WORKER_NAME}
        self.assertEqual(workers_after, workers_before)

    def test_startup_exit_and_eof_are_reaped(self):
        sources = {
            "startup_error": "import sys; print('synthetic startup failure', file=sys.stderr); sys.exit(2)",
            "early_eof": "import sys; sys.stdin.readline()",
            "stdout_eof_while_alive": "import os,time; os.close(1); time.sleep(30)",
        }
        for name, source in sources.items():
            with self.subTest(name=name):
                self.assert_readiness_failure(source)

    def test_malformed_and_invalid_discovery_replies_are_reaped(self):
        replies = {
            "malformed_json": "not json",
            "not_object": "[]",
            "rpc_error": json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32603}}),
            "missing_jsonrpc": json.dumps({"id": 1, "result": READY["result"]}),
            "wrong_jsonrpc": json.dumps(dict(READY, jsonrpc="1.0")),
            "wrong_id": json.dumps(dict(READY, id=2)),
            "boolean_id": json.dumps(dict(READY, id=True)),
            "missing_result": json.dumps({"jsonrpc": "2.0", "id": 1}),
            "invalid_result": json.dumps(dict(READY, result=[])),
            "wrong_protocol": json.dumps(dict(READY, result=dict(READY["result"], protocolVersion="2025-11-25"))),
            "missing_server": json.dumps(dict(READY, result={"protocolVersion": "2026-07-28"})),
            "invalid_server": json.dumps(dict(READY, result=dict(READY["result"], serverInfo=[]))),
            "wrong_server": json.dumps(dict(READY, result=dict(READY["result"], serverInfo={"name": "other"}))),
        }
        for name, reply in replies.items():
            with self.subTest(name=name):
                source = "import sys,time; sys.stdin.readline(); print(%r, flush=True); time.sleep(30)" % reply
                self.assert_readiness_failure(source)

    def test_silent_child_and_unterminated_frame_have_bounded_readiness(self):
        sources = {
            "silent": "import time; time.sleep(30)",
            "partial": "import sys,time; sys.stdin.readline(); sys.stdout.write('{'); sys.stdout.flush(); time.sleep(30)",
            "oversized": "import sys,time; sys.stdin.readline(); sys.stdout.write('x' * %d); sys.stdout.flush(); time.sleep(30)" % (MAX_FRAME_BYTES + 1),
        }
        for name, source in sources.items():
            with self.subTest(name=name):
                self.assert_readiness_failure(source, timeout=0.3)

    def test_close_reaps_child_despite_buffered_broken_pipe(self):
        source = "import sys; sys.stdin.readline(); print(%r, flush=True)" % json.dumps(READY)
        with self.child(source):
            client = McpFixtureClient(self.directory, self.directory / "unused.cap", "startup-fixture")
        client.process.wait(timeout=5)
        client.process.stdin.write("buffered before close")
        client.close()
        self.assert_reaped_and_closed(client.process)

    def test_constructor_waits_for_delayed_real_mcp_startup(self):
        entered = self.directory / "child-entered"
        release = self.directory / "release-child"
        source = """
import runpy, sys, time
from pathlib import Path
entered, release = map(Path, sys.argv[1:3])
entered.touch()
deadline = time.monotonic() + 15
while not release.exists():
    if time.monotonic() >= deadline:
        raise SystemExit('synthetic barrier was not released')
    time.sleep(0.01)
sys.argv = ['continuum_memory.mcp'] + sys.argv[3:]
runpy.run_module('continuum_memory.mcp', run_name='__main__')
"""
        with EphemeralHarness() as harness:
            outcome = {}
            finished = threading.Event()

            def construct():
                try:
                    outcome["client"] = harness.mcp("beta", "codex")
                except Exception as error:
                    outcome["error"] = error
                finally:
                    finished.set()

            arguments = [str(entered), str(release), "--data-dir", str(harness.data_dir),
                         "--capability-file", harness.projects["beta"]["capabilities"]["codex"]]
            constructor = threading.Thread(target=construct, name="fixture-startup-test-constructor")
            with self.child(source, arguments):
                constructor.start()
                try:
                    deadline = time.monotonic() + 5
                    while not entered.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(entered.exists(), "child never reached the startup barrier")
                    self.assertFalse(finished.wait(0.1), "constructor returned before the child started MCP")
                    release.touch()
                    self.assertTrue(finished.wait(5), "constructor did not finish after startup was released")
                    self.assertNotIn("error", outcome)
                    client = outcome["client"]
                    self.assertEqual(client.counter, 1)
                    self.assertEqual(client.request("ping")["result"], {})
                finally:
                    release.touch()
                    constructor.join(timeout=7)
                    if constructor.is_alive():
                        self.cleanup_processes()
                        constructor.join(timeout=2)
                    self.assertFalse(constructor.is_alive(), "constructor thread leaked")

    def test_readiness_preserves_real_modern_and_legacy_requests(self):
        with EphemeralHarness() as harness:
            modern = harness.mcp("alpha", "codex")
            legacy = harness.mcp("alpha", "claude")
            self.assertEqual(modern.counter, 1)
            self.assertEqual(legacy.counter, 1)
            self.assertEqual(modern.discover()["serverInfo"]["name"], "continuum-memory")
            self.assertEqual(len(modern.tools()), 6)
            self.assertEqual(modern.call("memory_search", {"query": "synthetic startup"})["cards"], [])
            uninitialized = legacy.request_legacy("tools/list")
            self.assertEqual(uninitialized["error"]["code"], -32602)
            initialized = legacy.request_legacy("initialize", {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "startup-legacy-fixture", "version": "1"},
            })
            self.assertEqual(initialized["result"]["protocolVersion"], "2025-11-25")
            self.assertEqual(len(legacy.request_legacy("tools/list")["result"]["tools"]), 6)
            search = legacy.request_legacy("tools/call", {
                "name": "memory_search", "arguments": {"query": "synthetic startup"},
            })
            self.assertEqual(search["result"]["structuredContent"]["cards"], [])


if __name__ == "__main__":
    unittest.main()
