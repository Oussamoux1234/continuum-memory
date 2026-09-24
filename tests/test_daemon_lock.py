"""Synthetic local vaults, real process locks/sockets, bounded fault injection."""

import errno
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from continuum_memory.client import DaemonClient
from continuum_memory.daemon import MemoryServer, serve
from continuum_memory.daemon_lock import DaemonLock, LOCK_MARKER
from continuum_memory.errors import MemoryError
from continuum_memory.storage import Store, paths

ROOT = Path(__file__).resolve().parents[1]


class DaemonLockTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-lock-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.project = Store.bootstrap(self.home, [
            {"name": "locks", "path_hint": "/fixture/locks", "providers": ["codex"]}
        ])["projects"][0]
        self.socket_path = paths(self.home)["socket"]
        self.lock_path = self.home / "memoryd.lock"
        self.client = DaemonClient(self.home, paths(self.home)["control"])

    def socket(self, path=None, listening=False):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind(str(path or self.socket_path))
        os.chmod(str(path or self.socket_path), 0o600)
        if listening:
            sock.listen(8)
        return sock

    def marked(self):
        with DaemonLock(self.home) as lock:
            lock.prepare_socket(self.socket_path)

    def start(self, gate=False):
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT)]),
                           PYTHONPYCACHEPREFIX=str(ROOT / "work" / "pycache"))
        command = [sys.executable, "-m", "continuum_memory.daemon", "--data-dir", str(self.home)]
        if gate:
            command = [sys.executable, "-c",
                       "import sys; sys.stdin.buffer.read(1); from continuum_memory.daemon import main; "
                       "raise SystemExit(main(sys.argv[1:]))", "--data-dir", str(self.home)]
        process = subprocess.Popen(command, stdin=subprocess.PIPE if gate else subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment)

        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            if process.stdin:
                process.stdin.close()
            process.stderr.close()
        self.addCleanup(cleanup)
        return process

    def ready(self, process):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail("daemon exited: " + process.stderr.read().decode())
            if self.socket_path.exists():
                try:
                    self.client.call("status", {"project": self.project["id"]})
                    return
                except MemoryError:
                    pass
            time.sleep(0.01)
        self.fail("daemon readiness deadline expired")

    def test_persistent_lock_marker_and_exec_descriptor_closure(self):
        with DaemonLock(self.home) as lock:
            lock.prepare_socket(self.socket_path)
            before = self.lock_path.stat()
            self.assertFalse(os.get_inheritable(lock.fd))
            child = subprocess.run([sys.executable, "-c",
                                    "import os,sys\ntry: os.fstat(int(sys.argv[1]))\n"
                                    "except OSError: sys.exit(0)\nsys.exit(1)", str(lock.fd)],
                                   close_fds=False, timeout=5, check=False)
            self.assertEqual(child.returncode, 0)
            self.assertEqual(self.lock_path.read_bytes(), LOCK_MARKER)
        with DaemonLock(self.home) as lock:
            lock.prepare_socket(self.socket_path)
            self.assertEqual(self.lock_path.stat().st_ino, before.st_ino)
            self.assertEqual(self.lock_path.read_bytes(), LOCK_MARKER)

    def test_losing_contender_never_opens_store_or_changes_lock(self):
        with DaemonLock(self.home) as lock:
            lock.prepare_socket(self.socket_path)
            with patch("continuum_memory.daemon.Store") as constructor:
                with self.assertRaises(MemoryError) as caught:
                    serve(self.home)
            self.assertEqual(caught.exception.code, "already_running")
            constructor.assert_not_called()
            self.assertEqual(self.lock_path.read_bytes(), LOCK_MARKER)
            self.assertFalse(self.socket_path.exists())

    def test_unsafe_lock_paths_fail_without_rewriting_or_blocking(self):
        target = self.home / "sentinel"
        target.write_bytes(b"SYNTHETIC-DO-NOT-CHANGE")
        os.chmod(str(target), 0o600)
        for kind in ("symlink", "hardlink", "fifo", "directory", "permissions"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    self.lock_path.symlink_to(target.name)
                elif kind == "hardlink":
                    os.link(str(target), str(self.lock_path))
                elif kind == "fifo":
                    os.mkfifo(str(self.lock_path), 0o600)
                elif kind == "directory":
                    self.lock_path.mkdir(mode=0o700)
                else:
                    self.lock_path.write_bytes(b"SYNTHETIC-DO-NOT-CHANGE")
                    os.chmod(str(self.lock_path), 0o644)
                started = time.monotonic()
                with self.assertRaises(MemoryError):
                    with DaemonLock(self.home):
                        self.fail("unsafe lock acquired")
                self.assertLess(time.monotonic() - started, 1)
                self.assertEqual(target.read_bytes(), b"SYNTHETIC-DO-NOT-CHANGE")
                if kind == "permissions":
                    self.assertEqual(self.lock_path.read_bytes(), b"SYNTHETIC-DO-NOT-CHANGE")
                if kind == "directory":
                    self.lock_path.rmdir()
                else:
                    self.lock_path.unlink()

    def test_foreign_owner_and_lock_replacement_fail_closed(self):
        real_fstat = os.fstat

        def foreign_file(fd):
            info = real_fstat(fd)
            # Target the lock, not the macOS parent-directory metadata FD.
            if not stat.S_ISREG(info.st_mode):
                return info
            fields = list(info)
            fields[4] = os.getuid() + 1
            return os.stat_result(fields)

        with patch("continuum_memory.security.os.fstat", side_effect=foreign_file):
            with self.assertRaises(MemoryError) as caught:
                with DaemonLock(self.home):
                    pass
        self.assertEqual(caught.exception.code, "unsafe_owner")
        with DaemonLock(self.home) as lock:
            lock.prepare_socket(self.socket_path)
            original = self.home / "original.lock"
            self.lock_path.rename(original)
            self.lock_path.write_bytes(LOCK_MARKER)
            os.chmod(str(self.lock_path), 0o600)
            with self.assertRaises(MemoryError) as changed:
                lock.check()
            self.assertEqual(changed.exception.code, "daemon_lock_changed")
        self.assertEqual(self.lock_path.read_bytes(), LOCK_MARKER)
        self.assertEqual(original.read_bytes(), LOCK_MARKER)

    def test_unmarked_legacy_socket_repeatedly_refused_and_invalid_marker_preserved(self):
        old = self.socket()
        old.close()
        inode = self.socket_path.stat().st_ino
        for _attempt in range(2):
            with self.assertRaises(MemoryError) as caught:
                with DaemonLock(self.home) as lock:
                    lock.prepare_socket(self.socket_path)
            self.assertEqual(caught.exception.code, "stale_socket_unverified")
            self.assertEqual(self.lock_path.read_bytes(), b"")
            self.assertEqual(self.socket_path.stat().st_ino, inode)
        self.lock_path.write_bytes(LOCK_MARKER[:9])
        with self.assertRaises(MemoryError) as caught:
            with DaemonLock(self.home) as lock:
                lock.prepare_socket(self.socket_path)
        self.assertEqual(caught.exception.code, "daemon_lock_invalid")
        self.assertEqual(self.lock_path.read_bytes(), LOCK_MARKER[:9])
        self.assertEqual(self.socket_path.stat().st_ino, inode)

    def test_stale_marked_socket_recovers_but_live_listener_is_preserved(self):
        self.marked()
        old = self.socket()
        old.close()
        with DaemonLock(self.home) as lock:
            lock.prepare_socket(self.socket_path)
            self.assertFalse(self.socket_path.exists())
        self.socket(listening=True)
        before = self.socket_path.stat().st_ino
        with self.assertRaises(MemoryError) as caught:
            with DaemonLock(self.home) as lock:
                lock.prepare_socket(self.socket_path)
        self.assertEqual(caught.exception.code, "already_running")
        self.assertEqual(self.socket_path.stat().st_ino, before)

    def test_ambiguous_probe_and_changed_socket_never_unlink(self):
        self.marked()
        old = self.socket()
        old.close()
        before = self.socket_path.stat().st_ino
        for failure in (socket.timeout(), PermissionError(errno.EACCES, "synthetic"),
                        FileNotFoundError(errno.ENOENT, "synthetic")):
            with self.subTest(failure=type(failure).__name__):
                with DaemonLock(self.home) as lock:
                    with patch.object(socket.socket, "connect", side_effect=failure):
                        with self.assertRaises(MemoryError) as caught:
                            lock.prepare_socket(self.socket_path)
                self.assertEqual(caught.exception.code, "socket_state_unknown")
                self.assertEqual(self.socket_path.stat().st_ino, before)
        replacement = self.home / "replacement.sock"
        self.socket(replacement)

        def replace_during_probe(*_args):
            os.replace(str(replacement), str(self.socket_path))
            raise ConnectionRefusedError(errno.ECONNREFUSED, "synthetic")

        with DaemonLock(self.home) as lock:
            with patch.object(socket.socket, "connect", side_effect=replace_during_probe):
                with self.assertRaises(MemoryError) as caught:
                    lock.prepare_socket(self.socket_path)
        self.assertEqual(caught.exception.code, "unsafe_socket")
        self.assertNotEqual(self.socket_path.stat().st_ino, before)

    def test_simultaneous_starts_have_one_owner(self):
        first, second = self.start(gate=True), self.start(gate=True)
        for process in (first, second):
            process.stdin.write(b"x")
            process.stdin.flush()
        deadline = time.monotonic() + 5
        while all(p.poll() is None for p in (first, second)) and time.monotonic() < deadline:
            time.sleep(0.01)
        losers = [p for p in (first, second) if p.poll() is not None]
        self.assertEqual(len(losers), 1)
        self.assertEqual(losers[0].returncode, 2)
        self.assertIn(b"already_running", losers[0].stderr.read())
        self.ready(second if losers[0] is first else first)

    def test_sigstop_owner_blocks_contender_then_sigkill_allows_restart(self):
        first = self.start()
        self.ready(first)
        agent = DaemonClient(self.home, Path(self.project["capabilities"]["codex"]))
        delivery = {"subject": "Recovery canary", "claim": "Synthetic durable draft",
                    "evidence": "Synthetic evidence", "source_handle": "fixture:recovery",
                    "disclosure": ["codex"], "idempotency_key": "fixture-delivery-1"}
        proposal = agent.call("propose", delivery)
        inode = self.socket_path.stat().st_ino
        os.kill(first.pid, signal.SIGSTOP)
        loser = self.start()
        self.assertEqual(loser.wait(timeout=5), 2)
        self.assertIn(b"already_running", loser.stderr.read())
        self.assertEqual(self.socket_path.stat().st_ino, inode)
        first.kill()
        first.wait(timeout=5)
        self.assertTrue(self.socket_path.exists())
        successor = self.start()
        self.ready(successor)
        self.assertEqual(agent.call("propose", delivery)["proposal_id"], proposal["proposal_id"])
        self.assertEqual(self.client.call("audit_verify", {})["status"], "valid")
        successor.terminate()
        self.assertEqual(successor.wait(timeout=5), 0)
        self.assertFalse(self.socket_path.exists())
        self.assertEqual(self.lock_path.read_bytes(), LOCK_MARKER)

    def test_startup_faults_cleanup_socket_store_signals_and_lock(self):
        originals = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        faults = (("continuum_memory.daemon.Store", OSError("store")),
                  ("continuum_memory.daemon.Kernel", OSError("kernel")),
                  ("continuum_memory.daemon.os.chmod", OSError("chmod")),
                  ("socket.socket.listen", OSError("listen")),
                  ("socket.socket.listen", KeyboardInterrupt()),
                  ("continuum_memory.daemon.selectors.DefaultSelector.register", OSError("register")))
        for target, error in faults:
            with self.subTest(target=target):
                kwargs = {"kernel_factory": lambda _store: (_ for _ in ()).throw(error)} if target.endswith("Kernel") else {}
                with patch(target, side_effect=error):
                    with self.assertRaises(type(error)):
                        serve(self.home, **kwargs)
                self.assertFalse(self.socket_path.exists())
                self.assertEqual({s: signal.getsignal(s) for s in originals}, originals)
                with DaemonLock(self.home):
                    pass
        real_signal = signal.signal

        def partial_registration(signum, handler):
            if signum == signal.SIGINT:
                raise ValueError("synthetic registration failure")
            return real_signal(signum, handler)

        with patch("continuum_memory.daemon.signal.signal", side_effect=partial_registration):
            with self.assertRaises(ValueError):
                serve(self.home)
        self.assertFalse(self.socket_path.exists())
        self.assertEqual({s: signal.getsignal(s) for s in originals}, originals)
        with patch.object(MemoryServer, "serve_forever", side_effect=KeyboardInterrupt):
            serve(self.home)
        self.assertFalse(self.socket_path.exists())
        self.assertEqual({s: signal.getsignal(s) for s in originals}, originals)

    def test_server_cleanup_preserves_replacement_socket(self):
        with closing(Store(self.home)) as store:
            server = MemoryServer(self.socket_path, store)
            self.addCleanup(server.server_close)
            replacement = self.home / "replacement.sock"
            self.socket(replacement)
            replacement_inode = replacement.stat().st_ino
            os.replace(str(replacement), str(self.socket_path))
            server.server_close()
            self.assertEqual(self.socket_path.stat().st_ino, replacement_inode)

    def test_cleanup_failure_still_closes_store_and_releases_lock(self):
        real_close = MemoryServer.server_close
        closed = []
        real_store_close = Store.close

        def fail_close(server):
            real_close(server)
            raise OSError("synthetic close failure")

        def record_close(store):
            closed.append(store)
            real_store_close(store)

        with patch.object(MemoryServer, "serve_forever", side_effect=KeyboardInterrupt), \
                patch.object(MemoryServer, "server_close", fail_close), patch.object(Store, "close", record_close):
            with self.assertRaises(OSError):
                serve(self.home)
        self.assertEqual(len(closed), 1)
        self.assertFalse(self.socket_path.exists())
        with DaemonLock(self.home):
            pass

    def test_open_to_lock_replacement_and_marker_write_failure_fail_closed(self):
        import fcntl
        real_flock = fcntl.flock

        def replace_during_acquisition(fd, operation):
            self.lock_path.rename(self.home / "superseded.lock")
            self.lock_path.write_bytes(LOCK_MARKER)
            os.chmod(str(self.lock_path), 0o600)
            real_flock(fd, operation)

        with patch("fcntl.flock", side_effect=replace_during_acquisition):
            with self.assertRaises(MemoryError) as caught:
                with DaemonLock(self.home):
                    pass
        self.assertEqual(caught.exception.code, "daemon_lock_changed")
        self.assertEqual(self.lock_path.read_bytes(), LOCK_MARKER)
        self.lock_path.unlink()
        with patch("continuum_memory.daemon_lock.os.write", return_value=0):
            with self.assertRaises(OSError):
                with DaemonLock(self.home) as lock:
                    lock.prepare_socket(self.socket_path)
        self.assertFalse(self.socket_path.exists())
        self.assertEqual(self.lock_path.read_bytes(), b"")
        self.marked()
