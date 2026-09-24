"""Real native daemon ownership and crash recovery in disposable synthetic vaults.

The accepted-claim setup uses the existing explicitly marked prototype fixture.
Every restarted/competing daemon uses the production kernel without that seam.
Process death is not host power-loss durability or a human-presence proof.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from continuum_memory.client import DaemonClient
from continuum_memory.errors import MemoryError
from continuum_memory.security import read_private
from continuum_memory.storage import Store, paths
from fixtures.harness import EphemeralHarness, private_test_home
from fixtures.process_io import read_line


ROOT = Path(__file__).resolve().parents[1]
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258


@unittest.skipUnless(os.name == "nt", "Full native Windows daemon lifecycle requires Windows")
class WindowsDaemonLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-native-lifecycle-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.environment = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT)]))
        self.outputs = {}

    def vault(self):
        home = private_test_home(self.temporary.name)
        project = Store.bootstrap(home, [
            {"name": "lifecycle", "path_hint": "/fixture/lifecycle", "providers": ["codex", "claude"]}
        ])["projects"][0]
        return home, project["id"], DaemonClient(home, paths(home)["control"])

    def start(self, mode, *arguments):
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--daemon-fixture", mode,
             *map(str, arguments)], env=self.environment,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.addCleanup(self.stop, process)
        return process

    def stop(self, process):
        if process not in self.outputs:
            if process.poll() is None:
                process.kill()
            self.outputs[process] = process.communicate(timeout=5)
        return self.outputs[process]

    def ready(self, process, control, project):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail("Production daemon exited before readiness: %r" % (self.stop(process),))
            try:
                result = control.call("status", {"project": project})
                self.assertEqual(result["approval_boundary"], "os_approval_unavailable")
                return result
            except MemoryError:
                time.sleep(0.02)
        self.fail("Production daemon did not become ready before its bounded deadline")

    def test_simultaneous_full_daemon_starts_have_one_owner_before_store(self):
        home, project, control = self.vault()
        markers = [self.root / ("store-attempt-%d" % index) for index in range(2)]
        children = [self.start("race", home, marker) for marker in markers]
        for child in children:
            self.assertEqual(read_line(child.stdout), b"armed\n")
        # Both interpreters are at the same pre-start barrier before release.
        for child in children:
            child.stdin.write(b"x")
            child.stdin.flush()
        deadline = time.monotonic() + 12
        while all(child.poll() is None for child in children) and time.monotonic() < deadline:
            time.sleep(0.02)
        losers = [index for index, child in enumerate(children) if child.poll() is not None]
        self.assertEqual(len(losers), 1)
        loser = losers[0]
        output, error = self.stop(children[loser])
        self.assertEqual(children[loser].returncode, 2, error)
        self.assertEqual(output, b"")
        self.assertEqual(json.loads(error)["error"]["code"], "pipe_endpoint_occupied")
        winner = 1 - loser
        self.ready(children[winner], control, project)
        self.assertFalse(markers[loser].exists(), "Losing daemon attempted to open Store")
        self.assertEqual(markers[winner].read_bytes(), b"attempted\n")
        self.assertEqual(control.call("audit_verify", {})["status"], "valid")

    def test_abrupt_full_daemon_restart_preserves_claim_and_audit_without_approval_fallback(self):
        with EphemeralHarness() as fixture:
            codex = fixture.mcp("alpha", "codex")
            claim, evidence = "Synthetic restart — 東京 — مرحبا", "Fixture-only reviewed evidence."
            proposal = codex.call("memory_propose", {
                "subject": "Windows restart fixture", "claim": claim, "evidence": evidence,
                "source_handle": "fixture:windows-restart", "disclosure": ["codex", "claude"],
                "idempotency_key": "windows-restart-fixture-001"})
            accepted = fixture.approve({"operation": "accept_proposal",
                "project": fixture.projects["alpha"]["id"], "proposal_id": proposal["proposal_id"]})["result"]
            before = fixture.control.call("audit_verify", {})
            binding = read_private(paths(fixture.data_dir)["ipc_binding"], 32)
            fixture.daemon.kill()  # Abrupt process death: no Python/SQLite cleanup.
            fixture.daemon.communicate(timeout=5)
            # Register with the harness so its own teardown closes this daemon
            # before attempting to remove the still-pinned synthetic vault.
            replacement = subprocess.Popen(
                [sys.executable, "-m", "continuum_memory.daemon", "--data-dir", str(fixture.data_dir)],
                env=self.environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            fixture.daemon = replacement
            project = fixture.projects["alpha"]["id"]
            self.ready(replacement, fixture.control, project)
            after = fixture.control.call("audit_verify", {})
            self.assertEqual(after["status"], "valid")
            self.assertEqual(after["head"], before["head"])
            self.assertEqual(after["events"], before["events"])
            self.assertEqual(read_private(paths(fixture.data_dir)["ipc_binding"], 32), binding)
            # Check the anchor before recall operations can append new activity.
            claude = fixture.mcp("alpha", "claude")
            found = claude.call("memory_search", {"query": "Windows restart fixture"})
            record = claude.call("memory_get", {"recall_id": found["recall_id"],
                "ids": [accepted["assertion_id"]]})["records"][0]
            self.assertEqual(record["claim"], claim)
            self.assertEqual(record["evidence"]["body"], evidence)
            self.assertEqual(record["provenance"]["source_agent"], "codex")
            history = fixture.control.call("show", {"project": project,
                "id": accepted["memory_id"], "history": True})
            self.assertEqual(len(history["versions"]), 1)
            self.assertEqual(history["versions"][0]["claim"], claim)
            with self.assertRaises(MemoryError) as denied:
                fixture.control.call("admin_preview", {"project": project,
                    "operation": "remember", "subject": "No fallback", "claim": "Must remain unavailable."})
            self.assertEqual(denied.exception.code, "approval_broker_unavailable")

    def test_exec_child_does_not_inherit_integrated_ownership_handles(self):
        from continuum_memory.windows_pipe import _PipeAPI

        home, project, control = self.vault()
        stop, child_ready = self.root / "exec-stop", self.root / "exec-ready"
        process_handle = []
        child_announced = []
        api = _PipeAPI()

        def release_child():
            stop.touch()
            if process_handle:
                handle = process_handle.pop()
                try:
                    self.assertEqual(api.kernel.WaitForSingleObject(handle, 5000), WAIT_OBJECT_0,
                                     "Synthetic exec child did not exit after its bounded release")
                finally:
                    api._close(handle)
            elif child_announced:
                # Even if opening the process handle failed, let the bounded
                # fixture observe release before temporary-directory cleanup.
                deadline = time.monotonic() + 5
                while not child_ready.with_suffix(".exited").exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(child_ready.with_suffix(".exited").exists())

        # Registered before the daemon cleanup: kill it first on an early failure,
        # then release/reap the child, and only then remove the fixture directory.
        self.addCleanup(release_child)
        daemon = self.start("inherit", home, child_ready, stop)
        message = json.loads(read_line(daemon.stdout))
        self.assertEqual(set(message), {"child_pid"})
        child_announced.append(True)
        handle = api.kernel.OpenProcess(0x00101000, False, message["child_pid"])
        self.assertTrue(handle)
        process_handle.append(handle)  # Retain one kernel identity; never reopen a recycled PID.
        self.assertEqual(api.kernel.WaitForSingleObject(handle, 0), WAIT_TIMEOUT)
        deadline = time.monotonic() + 10
        while not child_ready.exists() and time.monotonic() < deadline:
            self.assertEqual(api.kernel.WaitForSingleObject(handle, 0), WAIT_TIMEOUT)
            time.sleep(0.02)
        self.assertTrue(child_ready.exists())
        self.ready(daemon, control, project)
        self.stop(daemon)
        self.assertEqual(api.kernel.WaitForSingleObject(handle, 0), WAIT_TIMEOUT)
        # Inherited binding/database/ancestor pins would keep these renames
        # blocked. An inherited first pipe instance would block the restart.
        moved = home.with_name("released-vault")
        home.rename(moved)
        moved.rename(home)
        replacement = self.start("production", home)
        self.ready(replacement, control, project)
        self.assertEqual(control.call("audit_verify", {})["status"], "valid")
        self.assertEqual(api.kernel.WaitForSingleObject(handle, 0), WAIT_TIMEOUT)


def exec_child(ready, stop):
    """Never open the vault; stay alive across the parent daemon's abrupt death."""
    ready.touch()
    deadline = time.monotonic() + 45
    while not stop.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    ready.with_suffix(".exited").touch()


def daemon_child(mode, arguments):
    from continuum_memory import daemon
    from continuum_memory.kernel import Kernel

    home = Path(arguments[0])
    if mode == "race":
        original = daemon.Store

        def observed_store(path):
            Path(arguments[1]).write_bytes(b"attempted\n")
            return original(path)

        daemon.Store = observed_store  # Observe only; real Store and all guards run.
        print("armed", flush=True)
        if sys.stdin.buffer.read(1) != b"x":
            raise RuntimeError("Synthetic start barrier was not released")
    if mode == "inherit":
        child = None

        def kernel(store):
            nonlocal child
            # At this seam the full pipe pool, Store and binding guards are held.
            # close_fds=False deliberately tests each native handle's inherit flag.
            child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                "--exec-fixture", arguments[1], arguments[2]], close_fds=False,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(json.dumps({"child_pid": child.pid}), flush=True)
            return Kernel(store)

        try:
            daemon.serve(home, kernel_factory=kernel)
        finally:
            Path(arguments[2]).touch()
            if child is not None:
                child.wait(timeout=5)
        return 0
    return daemon.main(["--data-dir", str(home)])


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon-fixture":
        sys.stdout.reconfigure(newline="\n")
        raise SystemExit(daemon_child(sys.argv[2], sys.argv[3:]))
    if len(sys.argv) > 1 and sys.argv[1] == "--exec-fixture":
        exec_child(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        unittest.main()
