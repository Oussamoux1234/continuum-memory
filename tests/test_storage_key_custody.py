"""Filesystem/process-death custody evidence only; no native crypto substitutes."""

import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from continuum_memory import storage, storage_key_custody as custody
from continuum_memory.errors import MemoryError
from continuum_memory.security import write_private
from fixtures.key_custody import CRASH_EXIT, JOURNAL, NEW_KEY, OLD_KEY, custody_fault, digest


ROOT = Path(__file__).resolve().parents[1]
PROMOTION_BARRIERS = tuple(name + side for name in (
    "custody:next_fsync", "custody:pre_rename_dir_fsync", "custody:rename", "custody:post_rename_dir_fsync",
) for side in (":before", ":after"))


class StorageKeyCustodyTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-key-custody-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.vault = self.new_vault("vault")

    def new_vault(self, name):
        directory = self.root / name
        directory.mkdir(mode=0o700)
        write_private(directory / "storage.key", OLD_KEY)
        write_private(directory / "storage.key.next", NEW_KEY)
        return directory

    def promote(self, directory=None):
        custody.promote_prepared_key(directory or self.vault, digest(OLD_KEY), digest(NEW_KEY))

    def snapshot(self, directory=None):
        result = {}
        for path in (directory or self.vault).iterdir():
            info = path.lstat()
            content = path.read_bytes() if stat.S_ISREG(info.st_mode) else os.readlink(path) if path.is_symlink() else None
            result[path.name] = (info.st_ino, info.st_mode, info.st_nlink, content)
        return result

    def child(self, directory, barrier, operation="promote", death="exit"):
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join((str(ROOT / "src"), str(ROOT))),
                           PYTHONPYCACHEPREFIX=str(ROOT / "work" / "pycache"))
        completed = subprocess.run([sys.executable, "-m", "fixtures.key_custody", operation,
                                    str(directory), barrier, death], env=environment,
                                   capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, -signal.SIGKILL if death == "kill" else CRASH_EXIT, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")
        return completed

    def test_promotes_same_next_inode_without_third_key_file_and_retries(self):
        next_inode = (self.vault / "storage.key.next").stat().st_ino
        self.promote()
        active = self.vault / "storage.key"
        self.assertEqual(active.stat().st_ino, next_inode)
        self.assertEqual(active.stat().st_mode & 0o777, 0o600)
        self.assertEqual(active.read_bytes(), NEW_KEY)
        self.assertEqual(set(self.snapshot()), {"storage.key"})
        self.promote()
        self.assertEqual(active.stat().st_ino, next_inode)
        self.assertEqual(set(self.snapshot()), {"storage.key"})

    def test_each_real_process_exit_leaves_only_known_recoverable_key_names(self):
        for index, barrier in enumerate(PROMOTION_BARRIERS):
            with self.subTest(barrier=barrier):
                directory = self.new_vault("crash-%d" % index)
                next_inode = (directory / "storage.key.next").stat().st_ino
                self.child(directory, barrier)
                renamed = barrier in {"custody:rename:after", "custody:post_rename_dir_fsync:before",
                                      "custody:post_rename_dir_fsync:after"}
                self.assertEqual(set(self.snapshot(directory)), {"storage.key"} if renamed else {"storage.key", "storage.key.next"})
                self.assertEqual((directory / "storage.key").read_bytes(), NEW_KEY if renamed else OLD_KEY)
                self.promote(directory)
                self.assertEqual((directory / "storage.key").stat().st_ino, next_inode)
                self.assertEqual(set(self.snapshot(directory)), {"storage.key"})

    def test_sigkill_after_real_rename_has_same_known_custody_state(self):
        self.child(self.vault, "custody:rename:after", death="kill")
        self.assertEqual(set(self.snapshot()), {"storage.key"})
        self.assertEqual((self.vault / "storage.key").read_bytes(), NEW_KEY)
        self.promote()

    def test_fsync_and_rename_failures_do_not_create_untracked_keys(self):
        for index, barrier in enumerate(PROMOTION_BARRIERS):
            with self.subTest(barrier=barrier):
                directory = self.new_vault("error-%d" % index)
                with custody_fault(barrier) as fired:
                    with self.assertRaises(MemoryError):
                        self.promote(directory)
                self.assertEqual(fired, [barrier])
                self.assertLessEqual(set(self.snapshot(directory)), {"storage.key", "storage.key.next"})
                self.promote(directory)

    def test_native_fixture_wraps_real_custody_boundaries_without_claiming_native_proof(self):
        from continuum_memory import storage_rotation as rotation
        from fixtures.rotation import boundary_fault
        state = {"old_key_sha256": digest(OLD_KEY), "new_key_sha256": digest(NEW_KEY)}
        for index, barrier in enumerate(PROMOTION_BARRIERS):
            directory = self.new_vault("fixture-%d" % index)
            with boundary_fault(barrier) as fired:
                with self.assertRaises(MemoryError):
                    # Only the filesystem-only publication wrapper is invoked;
                    # no SQLCipher operation or approval provider runs here.
                    rotation._publish_key(directory, state)
            self.assertEqual(fired, [barrier])
            self.promote(directory)

    def test_missing_next_with_old_active_is_never_regenerated(self):
        (self.vault / "storage.key.next").unlink()
        before = self.snapshot()
        with self.assertRaises(MemoryError):
            self.promote()
        self.assertEqual(self.snapshot(), before)

    def test_published_matching_duplicate_is_retained_for_verified_cleanup(self):
        (self.vault / "storage.key").write_bytes(NEW_KEY)
        before = self.snapshot()
        self.promote()
        self.assertEqual(self.snapshot(), before)
        custody.remove_verified_rotation_material(self.vault, "storage.key.next", digest(NEW_KEY))
        self.assertEqual(set(self.snapshot()), {"storage.key"})

    def test_foreign_owner_and_malformed_expected_hashes_are_refused(self):
        before = self.snapshot()
        for old, new in (("bad", digest(NEW_KEY)), (digest(OLD_KEY), True),
                         (digest(OLD_KEY), digest(OLD_KEY))):
            with self.assertRaises(MemoryError):
                custody.promote_prepared_key(self.vault, old, new)
            self.assertEqual(self.snapshot(), before)
        original = os.fstat

        def foreign_owner(descriptor):
            info = original(descriptor)
            if stat.S_ISREG(info.st_mode):
                return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink, st_uid=os.getuid() + 1)
            return info

        # A non-root test cannot create a foreign-owned file; substitute only
        # fstat ownership evidence, never a cipher or approval result.
        with patch.object(custody.os, "fstat", side_effect=foreign_owner):
            with self.assertRaises(MemoryError):
                self.promote()
        self.assertEqual(self.snapshot(), before)

    def test_mismatched_short_or_unexpected_key_files_are_not_replaced(self):
        for index, (name, value) in enumerate((("storage.key", b"x" * 32), ("storage.key.next", b"x" * 32),
                                               ("storage.key.next", b""), ("storage.key.next", b"n" * 31),
                                               ("storage.key.next", b"n" * 33))):
            with self.subTest(name=name, size=len(value)):
                directory = self.new_vault("invalid-%d" % index)
                (directory / name).write_bytes(value)
                before = self.snapshot(directory)
                with self.assertRaises(MemoryError):
                    self.promote(directory)
                self.assertEqual(self.snapshot(directory), before)

    def test_symlink_hardlink_fifo_and_permissive_keys_are_preserved(self):
        for index, kind in enumerate(("symlink", "dangling", "hardlink", "fifo", "permissive")):
            with self.subTest(kind=kind):
                directory = self.new_vault("unsafe-%d" % index)
                path = directory / "storage.key.next"
                path.unlink()
                target = self.root / ("target-%d" % index)
                write_private(target, NEW_KEY)
                if kind in {"symlink", "dangling"}:
                    path.symlink_to(target if kind == "symlink" else self.root / "missing")
                elif kind == "hardlink":
                    os.link(target, path)
                elif kind == "fifo":
                    os.mkfifo(path, 0o600)
                else:
                    write_private(path, NEW_KEY)
                    path.chmod(0o644)
                before = self.snapshot(directory)
                with self.assertRaises(MemoryError):
                    self.promote(directory)
                self.assertEqual(self.snapshot(directory), before)
                self.assertEqual(target.read_bytes(), NEW_KEY)

    def test_parent_permissions_symlink_and_inode_swap_are_refused(self):
        self.vault.chmod(0o755)
        with self.assertRaises(MemoryError):
            self.promote()
        self.vault.chmod(0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.vault)
        with self.assertRaises(MemoryError):
            self.promote(alias)
        sync = os.fsync
        moved = self.root / "moved"
        swapped = []

        def swap_parent(descriptor):
            result = sync(descriptor)
            if not swapped and stat.S_ISDIR(os.fstat(descriptor).st_mode):
                self.vault.rename(moved)
                self.new_vault("vault")
                swapped.append(True)
            return result

        with patch.object(custody.os, "fsync", side_effect=swap_parent):
            with self.assertRaises(MemoryError):
                self.promote()
        self.assertEqual(swapped, [True])
        for directory in (self.vault, moved):
            self.assertEqual((directory / "storage.key").read_bytes(), OLD_KEY)
            self.assertEqual((directory / "storage.key.next").read_bytes(), NEW_KEY)

    def test_next_inode_replacement_after_fsync_is_refused_before_publication(self):
        sync = os.fsync
        swapped = []

        # Set the flag before fixture write_private recursively calls fsync.
        def guarded_swap(descriptor):
            if not swapped and stat.S_ISREG(os.fstat(descriptor).st_mode):
                swapped.append("swapping")
                result = sync(descriptor)
                replacement = self.vault / "fixture-replacement"
                write_private(replacement, NEW_KEY)
                os.replace(replacement, self.vault / "storage.key.next")
                return result
            return sync(descriptor)

        with patch.object(custody.os, "fsync", side_effect=guarded_swap):
            with self.assertRaises(MemoryError):
                self.promote()
        self.assertEqual((self.vault / "storage.key").read_bytes(), OLD_KEY)

    def test_legacy_reserved_residue_is_preserved_and_blocks_normal_admission(self):
        for index, name in enumerate((".storage.key.012345abcdef.tmp", ".storage.key.malformed.tmp")):
            directory = self.new_vault("legacy-%d" % index)
            residue = directory / name
            residue.symlink_to(directory / "missing")
            before = self.snapshot(directory)
            for operation in (lambda: custody.require_no_legacy_key_residue(directory),
                              lambda: storage.require_no_pending_rotation(directory), lambda: self.promote(directory)):
                with self.assertRaises(MemoryError):
                    operation()
            self.assertEqual(self.snapshot(directory), before)

    def test_residue_scan_is_bounded_nonrecursive_and_never_deletes(self):
        nested = self.vault / "unrelated"
        nested.mkdir(mode=0o700)
        write_private(nested / ".storage.key.012345abcdef.tmp", NEW_KEY)
        with patch.object(custody, "MAX_DIRECTORY_ENTRIES", 3):
            custody.require_no_legacy_key_residue(self.vault)
            write_private(self.vault / "extra", b"fixture")
            before = self.snapshot()
            with self.assertRaises(MemoryError):
                custody.require_no_legacy_key_residue(self.vault)
            self.assertEqual(self.snapshot(), before)

    def test_cleanup_removes_only_exact_matching_fixed_material(self):
        write_private(self.vault / "storage.rotation.json", JOURNAL)
        before = self.snapshot()
        for name, expected in (("storage.key", digest(OLD_KEY)), ("../storage.key.next", digest(NEW_KEY)),
                               ("storage.key.next", digest(OLD_KEY)), ("storage.rotation.json", digest(b"wrong"))):
            with self.assertRaises(MemoryError):
                custody.remove_verified_rotation_material(self.vault, name, expected)
            self.assertEqual(self.snapshot(), before)
        custody.remove_verified_rotation_material(self.vault, "storage.key.next", digest(NEW_KEY))
        custody.remove_verified_rotation_material(self.vault, "storage.rotation.json", digest(JOURNAL))
        self.assertEqual(set(self.snapshot()), {"storage.key"})
        self.assertEqual((self.vault / "storage.key").read_bytes(), OLD_KEY)

    def test_cleanup_refuses_unsafe_material_and_fsync_failure_is_not_success(self):
        path = self.vault / "storage.rotation.json"
        path.symlink_to(self.vault / "storage.key")
        before = self.snapshot()
        with self.assertRaises(MemoryError):
            custody.remove_verified_rotation_material(self.vault, "storage.rotation.json", digest(OLD_KEY))
        self.assertEqual(self.snapshot(), before)
        path.unlink()
        write_private(path, JOURNAL)
        with custody_fault("custody:cleanup_dir_fsync:before", cleanup=True):
            with self.assertRaises(MemoryError):
                custody.remove_verified_rotation_material(self.vault, "storage.rotation.json", digest(JOURNAL))
        self.assertFalse(path.exists())
        self.assertEqual((self.vault / "storage.key").read_bytes(), OLD_KEY)
        self.assertEqual((self.vault / "storage.key.next").read_bytes(), NEW_KEY)

    def test_cleanup_process_exits_do_not_touch_other_material(self):
        barriers = ("custody:unlink:before", "custody:unlink:after",
                    "custody:cleanup_dir_fsync:before", "custody:cleanup_dir_fsync:after")
        for index, (operation, name) in enumerate((("remove-next", "storage.key.next"),
                                                  ("remove-journal", "storage.rotation.json"))):
            for item, barrier in enumerate(barriers):
                directory = self.new_vault("cleanup-%d-%d" % (index, item))
                write_private(directory / "storage.rotation.json", JOURNAL)
                before = self.snapshot(directory)
                self.child(directory, barrier, operation=operation)
                after = self.snapshot(directory)
                self.assertEqual({key: value for key, value in after.items() if key != name},
                                 {key: value for key, value in before.items() if key != name})
                self.assertEqual(name in after, barrier == "custody:unlink:before")


if __name__ == "__main__":
    unittest.main()
