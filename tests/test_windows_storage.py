"""Real NTFS/SQLite storage evidence. No human approval or encryption fixture."""

import ctypes
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from continuum_memory.admission import AdmissionPolicy, POLICY_FILE
from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.security import (
    create_private_directory, ensure_private_regular, hold_private_binding,
    read_private, replace_private, write_private,
)
from continuum_memory.storage import Store, _connect, paths
from continuum_memory.windows_boundary import WindowsBoundary, _RenameInfo
from fixtures.windows_acl import set_fixture_acl


PROJECTS = [{"name": "native fixture", "path_hint": "/fixture/native", "providers": ["codex"]}]


class ConnectionLifetimeTest(unittest.TestCase):
    def test_failed_close_keeps_guard_until_owner_thread_closes(self):
        from continuum_memory.windows_storage import GuardedConnection

        class LifecycleGuard:
            closed = False
            validations = 0

            def validate(self):
                self.validations += 1

            def close(self):
                self.closed = True

        # Real SQLite thread-affinity error, synthetic lifecycle guard only;
        # native filesystem pinning is covered by NativeWindowsStorageTest.
        connection = sqlite3.connect(":memory:", factory=GuardedConnection)
        guard = connection.guard = LifecycleGuard()
        errors = []

        def wrong_thread():
            try:
                connection.close()
            except sqlite3.ProgrammingError as error:
                errors.append(type(error))

        worker = threading.Thread(target=wrong_thread)
        worker.start()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [sqlite3.ProgrammingError])
        self.assertIs(connection.guard, guard)
        self.assertFalse(guard.closed)
        try:
            self.assertEqual(connection.execute("SELECT 42").fetchone(), (42,))
            self.assertEqual(guard.validations, 1)
        finally:
            connection.close()
        self.assertTrue(guard.closed)
        self.assertIsNone(connection.guard)


class RenameEncodingTest(unittest.TestCase):
    """Pure Win32 call-boundary checks, not native filesystem evidence."""

    def test_absolute_utf16_target_has_null_root_and_bounded_zero_padding(self):
        boundary = object.__new__(WindowsBoundary)
        boundary.kernel = mock.Mock()
        destination = "C:\\fixture\\méta-" + chr(0x1F9E0) + ".head"
        encoded = destination.encode("utf-16-le")
        self.assertGreater(len(encoded), len(destination) * 2)

        def capture(source, information_class, buffer, size):
            info = _RenameInfo.from_buffer(buffer)
            self.assertEqual(source, 123)
            self.assertEqual(information_class, 3)
            self.assertEqual(info.replace, 1)
            self.assertIsNone(info.root)
            self.assertEqual(info.length, len(encoded))
            self.assertEqual(size, ctypes.sizeof(_RenameInfo) + len(encoded) + 2)
            self.assertEqual(buffer.raw[_RenameInfo.name.offset:_RenameInfo.name.offset + info.length], encoded)
            self.assertEqual(buffer.raw[_RenameInfo.name.offset + info.length:],
                             b"\0" * (size - _RenameInfo.name.offset - info.length))
            return True

        boundary.kernel.SetFileInformationByHandle.side_effect = capture
        boundary._rename(123, destination)
        boundary.kernel.SetFileInformationByHandle.assert_called_once()

    def test_ambiguous_destinations_never_reach_native_api(self):
        boundary = object.__new__(WindowsBoundary)
        boundary.kernel = mock.Mock()
        for destination in ("relative.head", "C:relative.head", "\\\\server\\share\\head",
                            "C:\\fixture\\head:stream", "C:\\fixture\\head\0suffix",
                            "C:\\fixture\\head.", "C:\\fixture\\head "):
            with self.subTest(destination=destination), self.assertRaises(MemoryError):
                boundary._rename(123, destination)
        boundary.kernel.SetFileInformationByHandle.assert_not_called()


@unittest.skipUnless(os.name == "nt", "Native Windows storage evidence requires Windows")
class NativeWindowsStorageTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-win-store-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "vault"
        create_private_directory(self.home)
        self.boundary = WindowsBoundary()

    def bootstrap(self):
        return Store.bootstrap(self.home, PROJECTS)

    def test_sqlite_files_inherit_only_owner_access(self):
        self.bootstrap()
        store = Store(self.home)
        try:
            self.assertIsNone(store.owner_uid)
            store.connection.execute("INSERT INTO metadata VALUES ('native-fixture','yes')")
            for suffix in ("", "-wal", "-shm"):
                path = Path(str(paths(self.home)["db"]) + suffix)
                self.assertTrue(path.is_file(), suffix)
                ensure_private_regular(path)
            self.assertEqual(store.verify_audit()["status"], "valid")
        finally:
            store.close()

    def test_inherited_leaf_requires_its_private_immediate_parent(self):
        leaf = self.home / "inherited"
        leaf.write_bytes(b"synthetic")
        self.assertEqual(read_private(leaf), b"synthetic")
        set_fixture_acl(self.home, broad=True)
        with self.assertRaises(MemoryError):
            read_private(leaf)

    def test_directory_creation_never_repairs_existing_acl(self):
        occupied = self.root / "existing"
        occupied.mkdir()
        with self.assertRaises(MemoryError):
            create_private_directory(occupied)
        with self.assertRaises(MemoryError):
            self.boundary.inspect(occupied, directory=True)
        nested = self.home / "one" / "two"
        create_private_directory(nested, parents=True)
        self.boundary.inspect(nested, directory=True)
        self.boundary.inspect(nested.parent, directory=True)
        absent = next(chr(letter) + ":\\" for letter in range(90, 64, -1)
                      if self.boundary.kernel.GetDriveTypeW(chr(letter) + ":\\") == 1)
        with mock.patch("continuum_memory.security.path_exists", side_effect=AssertionError("must refuse volume first")):
            with self.assertRaises(MemoryError):
                create_private_directory(Path(absent) / "never-created" / "vault", parents=True)

    def test_atomic_replace_preserves_full_content_and_rename_abi(self):
        self.assertEqual(_RenameInfo.root.offset, 8)
        self.assertEqual(_RenameInfo.length.offset, 16)
        self.assertEqual(_RenameInfo.name.offset, 20)
        path = self.home / "méta.head"
        write_private(path, b"before")
        before = self.boundary.inspect(path)
        replace_private(path, b"after" * 100)
        self.assertEqual(read_private(path), b"after" * 100)
        self.assertNotEqual(before, self.boundary.inspect(path))
        self.assertEqual(list(self.home.iterdir()), [path])

    def test_absolute_replace_keeps_source_parent_and_ancestor_pinned_at_native_call(self):
        path = self.home / ("méta-" + chr(0x1F9E0) + ".head")
        write_private(path, b"before")
        original = WindowsBoundary._rename
        source_identities = []
        program = """import json, pathlib, sys
failures = []
for raw in sys.argv[1:]:
    source = pathlib.Path(raw)
    try: source.rename(source.with_name(source.name + '-moved'))
    except OSError: failures.append(True)
    else: failures.append(False)
print(json.dumps(failures))
"""

        def checked_rename(boundary, source, destination):
            self.assertEqual(destination, str(path))
            source_identities.append(boundary._info(source, False))
            siblings = [entry for entry in self.home.iterdir() if entry != path]
            self.assertEqual(len(siblings), 1)
            result = subprocess.run(
                [sys.executable, "-c", program, str(siblings[0]), str(self.home), str(self.root)],
                capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout), [True, True, True])
            # Real native rename follows the adversarial process attempts while
            # exactly the same source/parent/ancestor handles remain held.
            original(boundary, source, destination)
            self.assertTrue(boundary._info(source, False) == source_identities[0])

        with mock.patch.object(WindowsBoundary, "_rename", checked_rename):
            replace_private(path, b"after")
        self.assertEqual(len(source_identities), 1)
        self.assertTrue(self.boundary.inspect(path) == source_identities[0])
        self.assertEqual(read_private(path), b"after")
        self.assertEqual(list(self.home.iterdir()), [path])

    def test_failed_replace_preserves_old_target_and_removes_exact_temp(self):
        path = self.home / "head"
        write_private(path, b"before")
        with mock.patch.object(WindowsBoundary, "_rename", side_effect=RuntimeError("fixture")):
            with self.assertRaisesRegex(RuntimeError, "fixture"):
                replace_private(path, b"after")
        self.assertEqual(read_private(path), b"before")
        self.assertEqual(list(self.home.iterdir()), [path])

    def test_replace_refuses_link_target_without_writing_referent(self):
        target = self.home / "target"
        write_private(target, b"sentinel")
        link = self.home / "head"
        link.symlink_to(target)
        with self.assertRaises(MemoryError):
            replace_private(link, b"changed")
        self.assertEqual(target.read_bytes(), b"sentinel")

    def test_binding_lifetime_blocks_child_writes_truncate_delete_and_rename(self):
        self.bootstrap()
        binding = paths(self.home)["ipc_binding"]
        original = read_private(binding)
        self.assertEqual(len(original), 32)
        program = """import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); failures = []
for operation in (lambda: p.write_bytes(b'x'), lambda: p.open('ab'),
                  lambda: p.unlink(), lambda: p.rename(p.with_name('moved')),
                  lambda: p.parent.rename(p.parent.with_name('moved-vault'))):
    try: operation()
    except OSError: failures.append(True)
    else: failures.append(False)
print(json.dumps(failures))
"""
        with hold_private_binding(binding) as value:
            self.assertEqual(value, original)
            result = subprocess.run([sys.executable, "-c", program, str(binding)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [True] * 5)
        self.assertEqual(read_private(binding), original)
        binding.rename(binding.with_name("released"))

    def test_missing_short_oversized_and_occupied_binding_fail_closed(self):
        binding = paths(self.home)["ipc_binding"]
        with self.assertRaises(MemoryError):
            with hold_private_binding(binding):
                self.fail("missing binding accepted")
        for data in (b"", b"x" * 31, b"x" * 33):
            write_private(binding, data)
            with self.assertRaises(MemoryError):
                with hold_private_binding(binding):
                    self.fail("invalid binding accepted")
            with self.assertRaises(MemoryError) as caught:
                self.bootstrap()
            self.assertEqual(caught.exception.code, "already_initialized")
            self.assertEqual(binding.read_bytes(), data)
            binding.unlink()

    def test_database_and_vault_pinned_until_close(self):
        self.bootstrap()
        store = Store(self.home)
        db = paths(self.home)["db"]
        try:
            for source, destination in ((db, db.with_name("renamed.db")), (self.home, self.root / "renamed")):
                with self.assertRaises(OSError):
                    source.rename(destination)
        finally:
            store.close()
        db.rename(db.with_name("renamed.db"))
        self.home.rename(self.root / "released")

    def test_unsafe_sidecars_rejected_before_sqlite_open_or_any_pragma(self):
        self.bootstrap()
        db = paths(self.home)["db"]
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(db) + suffix)
            write_private(sidecar, b"synthetic-sidecar-sentinel")
            set_fixture_acl(sidecar, broad=True)
            with self.subTest(suffix=suffix), mock.patch("continuum_memory.windows_storage.sqlite3.connect") as connect:
                with self.assertRaises(MemoryError):
                    _connect(db)
                connect.assert_not_called()
            self.assertEqual(sidecar.read_bytes(), b"synthetic-sidecar-sentinel")
            sidecar.unlink()
        target = self.home / "external-sentinel"
        write_private(target, b"untouched")
        sidecar = Path(str(db) + "-wal")
        sidecar.symlink_to(target)
        with self.assertRaises(MemoryError):
            _connect(db)
        self.assertEqual(target.read_bytes(), b"untouched")

    def test_non_inheriting_vault_refused_before_sqlite_can_create_sidecars(self):
        self.bootstrap()
        db = paths(self.home)["db"]
        set_fixture_acl(self.home)  # Private but intentionally not OI|CI.
        before = {entry.name: entry.read_bytes() for entry in self.home.iterdir() if entry.is_file()}
        with mock.patch("continuum_memory.windows_storage.sqlite3.connect") as connect:
            with self.assertRaises(MemoryError):
                _connect(db)
            connect.assert_not_called()
        after = {entry.name: entry.read_bytes() for entry in self.home.iterdir() if entry.is_file()}
        self.assertEqual(after, before)

    def test_acl_and_hardlink_change_detected_before_later_statements(self):
        self.bootstrap()
        store = Store(self.home)
        db = paths(self.home)["db"]
        alias = self.home / "alias"
        try:
            set_fixture_acl(db, broad=True)
            with self.assertRaises(MemoryError):
                store.connection.execute("CREATE TABLE forbidden(value)")
            set_fixture_acl(db)
            os.link(db, alias)
            with self.assertRaises(MemoryError):
                store.connection.cursor().execute("CREATE TABLE forbidden(value)")
            alias.unlink()
            self.assertIsNone(store.connection.execute("SELECT name FROM sqlite_master WHERE name='forbidden'").fetchone())
        finally:
            if alias.exists():
                alias.unlink()
            set_fixture_acl(db)
            store.close()

    def test_partial_connect_and_configuration_failure_release_all_handles(self):
        self.bootstrap()
        db = paths(self.home)["db"]
        for patch in (
            mock.patch("continuum_memory.windows_storage.sqlite3.connect", side_effect=sqlite3.OperationalError("fixture")),
            mock.patch("continuum_memory.storage._configure_connection", side_effect=RuntimeError("fixture")),
        ):
            with patch, self.assertRaises((sqlite3.Error, RuntimeError)):
                _connect(db)
            moved = self.home.with_name("moved")
            self.home.rename(moved)
            moved.rename(self.home)

    def test_unsafe_policy_acl_refused_and_real_owner_approval_unavailable(self):
        self.bootstrap()
        policy = self.home / POLICY_FILE
        write_private(policy, b'{"version":1}')
        set_fixture_acl(policy, broad=True)
        with self.assertRaises(MemoryError) as caught:
            AdmissionPolicy.load(self.home)
        self.assertEqual(caught.exception.code, "admission_policy_invalid")
        policy.unlink()
        store = Store(self.home)
        try:
            from continuum_memory.storage import load_capability
            control = store.authenticate(load_capability(paths(self.home)["control"])["token"])
            before = store.connection.execute("SELECT count(*) FROM admin_challenges").fetchone()[0]
            project = store.connection.execute("SELECT id FROM projects").fetchone()[0]
            with self.assertRaises(MemoryError) as denied:
                Kernel(store).admin_preview(control, {"operation": "remember", "project": project,
                                                     "subject": "fixture", "claim": "not approved"})
            self.assertEqual(denied.exception.code, "approval_broker_unavailable")
            self.assertEqual(store.connection.execute("SELECT count(*) FROM admin_challenges").fetchone()[0], before)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
