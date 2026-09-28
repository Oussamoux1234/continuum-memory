"""Synthetic native ACL fixtures; never modify real vaults or host policy."""

import ctypes
import errno
import os
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from continuum_memory import macos_acl
from continuum_memory.daemon_lock import DaemonLock
from continuum_memory.errors import MemoryError
from continuum_memory.security import (
    ensure_private_directory, ensure_private_regular, ensure_private_socket,
    read_private, write_private,
)
from continuum_memory.storage import Store, _connect, paths


class FakeACL:
    """Inject native ABI failures; native fixture tests below prove real behavior."""
    def __init__(self, *, pointer=101, query_errno=0, size=44, baseline_size=44,
                 entry_status=-1, entry_errno=errno.EINVAL, entry_pointer=None):
        self.pointer = pointer
        self.query_errno = query_errno
        self.entry_status = entry_status
        self.entry_errno = entry_errno
        self.entry_pointer = entry_pointer
        self.acl_init = Mock(return_value=202)
        self.acl_valid = Mock(return_value=0)
        self.acl_size = Mock(side_effect=lambda acl: baseline_size if acl == 202 else size)
        self.acl_free = Mock(return_value=0)
        self.acl_get_fd_np = Mock(side_effect=self.query)
        self.acl_get_link_np = Mock(side_effect=self.query)
        self.acl_get_entry = Mock(side_effect=self.entry)

    def query(self, target, kind):
        if ctypes.get_errno() != 0:
            raise AssertionError("query errno must be reset")
        ctypes.set_errno(self.query_errno)
        return self.pointer

    def entry(self, acl, index, output):
        if ctypes.get_errno() != 0:
            raise AssertionError("entry errno must be reset")
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = self.entry_pointer
        ctypes.set_errno(self.entry_errno)
        return self.entry_status


class MacOSACLAPITest(unittest.TestCase):
    def setUp(self):
        self.metadata = SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600,
                                        st_nlink=1, st_uid=501, st_gid=20, st_ctime_ns=1)

    def check(self, library):
        ctypes.set_errno(errno.EINVAL)  # stale errno cannot authorize anything
        macos_acl._check_acl(library, library.acl_get_fd_np, 7)

    def test_valid_allocated_empty_acl_is_accepted_and_every_allocation_freed(self):
        library = FakeACL()
        self.check(library)
        self.assertEqual([call.args[0] for call in library.acl_free.call_args_list], [202, 101])
        self.assertEqual(library.acl_get_fd_np.call_args.args, (7, macos_acl.ACL_TYPE_EXTENDED))
        self.assertEqual(library.acl_get_entry.call_args.args[1], macos_acl.ACL_FIRST_ENTRY)

    def test_absent_acl_accepts_only_fresh_enoent(self):
        self.check(FakeACL(pointer=None, query_errno=errno.ENOENT))
        for code in (0, errno.EINVAL, errno.EIO, errno.EACCES, errno.ENOMEM, errno.ENOTSUP, errno.EBADF):
            with self.subTest(code=code), self.assertRaises(ValueError):
                self.check(FakeACL(pointer=None, query_errno=code))

    def test_nonempty_invalid_and_unbounded_acl_are_refused_and_freed(self):
        for size in (-1, 0, 43, 45, 68, macos_acl.MAX_ACL_BYTES + 1):
            with self.subTest(size=size):
                library = FakeACL(size=size)
                with self.assertRaises((ValueError, MemoryError)):
                    self.check(library)
                self.assertEqual(library.acl_free.call_count, 2)
        library = FakeACL()
        library.acl_valid.side_effect = [0, -1]
        with self.assertRaises(ValueError):
            self.check(library)
        self.assertEqual(library.acl_free.call_count, 2)

    def test_failed_or_malformed_baseline_is_refused_without_leaking_query_acl(self):
        for size in (-1, 0, macos_acl.MAX_ACL_BYTES + 1):
            with self.subTest(size=size):
                library = FakeACL(baseline_size=size)
                with self.assertRaises(ValueError):
                    self.check(library)
                self.assertEqual(library.acl_free.call_count, 2)
        library = FakeACL()
        library.acl_init.return_value = None
        with self.assertRaises(ValueError):
            self.check(library)
        library.acl_free.assert_called_once_with(101)
        library = FakeACL()
        library.acl_valid.return_value = -1
        with self.assertRaises(ValueError):
            self.check(library)
        self.assertEqual(library.acl_free.call_count, 2)

    def test_entry_status_errno_and_pointer_contradictions_are_refused(self):
        for status, code, pointer in ((0, 0, 303), (0, 0, None), (1, 0, None),
                                      (-1, 0, None), (-1, errno.EIO, None),
                                      (-1, errno.EINVAL, 303)):
            with self.subTest(status=status, code=code, pointer=pointer):
                library = FakeACL(entry_status=status, entry_errno=code, entry_pointer=pointer)
                with self.assertRaises(ValueError):
                    self.check(library)
                self.assertEqual(library.acl_free.call_count, 2)

    def test_release_failure_never_reports_success_and_other_allocation_is_freed(self):
        for failed_pointer in (101, 202):
            with self.subTest(pointer=failed_pointer):
                library = FakeACL()
                library.acl_free.side_effect = lambda value: -1 if value == failed_pointer else 0
                with self.assertRaises(ValueError):
                    self.check(library)
                self.assertEqual(library.acl_free.call_count, 2)

    def test_missing_api_and_query_failures_have_content_free_errors(self):
        for failure in (OSError("sensitive-path"), AttributeError("sensitive-symbol"),
                        TypeError("sensitive-value"), ValueError("sensitive-value")):
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(macos_acl.sys, "platform", "darwin"), \
                    patch.object(macos_acl.os, "fstat", return_value=self.metadata), \
                    patch.object(macos_acl, "_library", side_effect=failure):
                with self.assertRaises(MemoryError) as caught:
                    macos_acl.require_no_acl_fd(7, self.metadata)
                self.assertEqual(caught.exception.code, "acl_unavailable")
                self.assertNotIn("sensitive", str(caught.exception.as_dict()))

    def test_enoent_needs_unchanged_descriptor_metadata_before_and_after_query(self):
        for field in vars(self.metadata):
            changed = SimpleNamespace(**vars(self.metadata))
            setattr(changed, field, getattr(changed, field) + 1)
            for position in (0, 1):
                observations = [self.metadata, self.metadata]
                observations[position] = changed
                with self.subTest(field=field, position=position), \
                        patch.object(macos_acl.sys, "platform", "darwin"), \
                        patch.object(macos_acl.os, "fstat", side_effect=observations), \
                        patch.object(macos_acl, "_library", return_value=FakeACL(pointer=None, query_errno=errno.ENOENT)):
                    with self.assertRaises(MemoryError) as caught:
                        macos_acl.require_no_acl_fd(7, self.metadata)
                    self.assertEqual(caught.exception.code, "unsafe_file")

    def test_other_platforms_do_not_load_darwin_or_touch_descriptors(self):
        for platform in ("linux", "win32"):
            with self.subTest(platform=platform), patch.object(macos_acl.sys, "platform", platform), \
                    patch.object(macos_acl, "_library") as library, patch.object(macos_acl.os, "fstat") as fstat:
                macos_acl.require_no_acl_fd(-1, self.metadata)
                macos_acl.require_no_acl_path(Path("not-a-real-path"), self.metadata)
                library.assert_not_called()
                fstat.assert_not_called()

    def test_fixed_library_and_explicit_opaque_pointer_abi(self):
        library = Mock()
        with patch.object(macos_acl.ctypes, "CDLL", return_value=library) as load:
            self.assertIs(macos_acl._library.__wrapped__(), library)
        load.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
        self.assertEqual(library.acl_get_fd_np.argtypes, [ctypes.c_int, ctypes.c_int])
        self.assertIs(library.acl_get_fd_np.restype, ctypes.c_void_p)
        self.assertEqual(library.acl_get_link_np.argtypes, [ctypes.c_char_p, ctypes.c_int])
        self.assertIs(library.acl_get_link_np.restype, ctypes.c_void_p)
        self.assertIs(library.acl_size.restype, ctypes.c_ssize_t)


@unittest.skipUnless(sys.platform == "darwin", "native macOS extended ACL fixtures")
class NativeMacOSACLTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cm-acl-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)

    def add_acl(self, path, entry="everyone allow read,readattr,readextattr,readsecurity"):
        subprocess.run(["/bin/chmod", "+a", entry, str(path)], check=True,
                       capture_output=True, timeout=5)

    def test_no_acl_directory_file_and_socket_are_accepted(self):
        ensure_private_directory(self.home)
        target = self.home / "synthetic.cap"
        write_private(target, b"synthetic")
        ensure_private_regular(target)
        self.assertEqual(read_private(target), b"synthetic")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
            address = self.home / "memoryd.sock"
            endpoint.bind(str(address))
            address.chmod(0o600)
            ensure_private_socket(address)

    def test_python_without_eventonly_export_uses_same_native_boundary(self):
        target = self.home / "synthetic.cap"
        write_private(target, b"synthetic")
        older_os = SimpleNamespace(**{key: getattr(os, key) for key in
                                     ("O_NOFOLLOW", "O_NONBLOCK", "open", "close", "fstat", "fsencode")})
        with patch.object(macos_acl, "os", older_os):
            ensure_private_directory(self.home)
            ensure_private_regular(target)
            self.add_acl(target)
            with self.assertRaises(MemoryError) as caught:
                ensure_private_regular(target)
            self.assertEqual(caught.exception.code, "unsafe_permissions")
            for flag in ("O_NOFOLLOW", "O_NONBLOCK"):
                incomplete = SimpleNamespace(**{key: value for key, value in vars(older_os).items() if key != flag})
                with patch.object(macos_acl, "os", incomplete), self.assertRaises(MemoryError) as caught:
                    ensure_private_directory(self.home)
                self.assertEqual(caught.exception.code, "acl_unavailable")

    def test_allow_deny_and_owner_only_acls_are_all_refused(self):
        import pwd
        owner = pwd.getpwuid(os.getuid()).pw_name
        for index, entry in enumerate(("everyone allow read", "everyone deny writeextattr",
                                       "user:%s allow read" % owner)):
            for kind in ("file", "directory"):
                with self.subTest(entry=entry, kind=kind):
                    target = self.home / (kind + str(index))
                    if kind == "file":
                        write_private(target, b"synthetic")
                        check, expected_mode = ensure_private_regular, 0o600
                    else:
                        target.mkdir(mode=0o700)
                        check, expected_mode = ensure_private_directory, 0o700
                    self.add_acl(target, entry)
                    self.assertEqual(stat.S_IMODE(target.stat().st_mode), expected_mode)
                    with self.assertRaises(MemoryError) as caught:
                        check(target)
                    self.assertEqual(caught.exception.code, "unsafe_permissions")

    def test_socket_acl_is_refused_without_changing_mode(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
            address = self.home / "memoryd.sock"
            endpoint.bind(str(address))
            address.chmod(0o600)
            self.add_acl(address)
            self.assertEqual(stat.S_IMODE(address.stat().st_mode), 0o600)
            with self.assertRaises(MemoryError) as caught:
                ensure_private_socket(address)
            self.assertEqual(caught.exception.code, "unsafe_permissions")

    def test_socket_disappearance_and_replacement_after_query_are_refused(self):
        original_check = macos_acl._check_acl
        for replacement in (False, True):
            with self.subTest(replacement=replacement), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as endpoint:
                address = self.home / ("socket-%s" % replacement)
                target = self.home / ("target-%s" % replacement)
                write_private(target, b"untouched")
                endpoint.bind(str(address))
                address.chmod(0o600)

                def remove_after_query(library, query, path):
                    original_check(library, query, path)
                    address.unlink()
                    if replacement:
                        address.symlink_to(target)

                with patch.object(macos_acl, "_check_acl", side_effect=remove_after_query):
                    with self.assertRaises(MemoryError):
                        ensure_private_socket(address)
                self.assertEqual(target.read_bytes(), b"untouched")

    def test_inherited_file_and_directory_acls_are_refused(self):
        self.add_acl(self.home, "everyone allow read,file_inherit,directory_inherit")
        target = self.home / "child"
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        directory = self.home / "directory"
        directory.mkdir(mode=0o700)
        for path, check in ((target, ensure_private_regular), (directory, ensure_private_directory)):
            with self.subTest(kind=path.name):
                with self.assertRaises(MemoryError) as caught:
                    check(path)
                self.assertEqual(caught.exception.code, "unsafe_permissions")

    def test_read_refuses_existing_acl_and_acl_added_after_read(self):
        target = self.home / "synthetic.cap"
        write_private(target, b"synthetic")
        original_read = os.read
        changed = False

        def change_after_read(fd, size):
            nonlocal changed
            result = original_read(fd, size)
            if not changed:
                changed = True
                self.add_acl(target)
            return result

        with patch("continuum_memory.security.os.read", side_effect=change_after_read):
            with self.assertRaises(MemoryError) as caught:
                read_private(target)
        self.assertEqual(caught.exception.code, "unsafe_permissions")
        with patch("continuum_memory.security.os.read") as reader:
            with self.assertRaises(MemoryError):
                read_private(target)
            reader.assert_not_called()
        self.assertEqual(target.read_bytes(), b"synthetic")

    def test_parent_acl_refuses_write_without_creating_file(self):
        self.add_acl(self.home)
        target = self.home / "not-created"
        with self.assertRaises(MemoryError):
            write_private(target, b"synthetic")
        self.assertFalse(target.exists())

    def test_directory_entry_change_refuses_daemon_before_lock_creation(self):
        original_open = os.open
        changed = False

        def change_before_metadata_open(path, flags, *args, **kwargs):
            nonlocal changed
            if Path(path) == self.home and not changed:
                changed = True
                fd = original_open(self.home / "synthetic-concurrent-entry",
                                   os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            return original_open(path, flags, *args, **kwargs)

        with patch.object(macos_acl.os, "open", side_effect=change_before_metadata_open):
            with self.assertRaises(MemoryError) as caught:
                with DaemonLock(self.home):
                    self.fail("changed directory must not acquire a daemon lock")
        self.assertTrue(changed)
        self.assertEqual(caught.exception.code, "unsafe_file")
        self.assertEqual(caught.exception.message, "Private material changed during permission validation.")
        self.assertFalse((self.home / "memoryd.lock").exists())

    def test_inherited_acl_raced_into_new_file_is_refused_before_bytes(self):
        target = self.home / "empty-residue"
        original_open = os.open

        def inherit_before_create(path, flags, *args, **kwargs):
            if Path(path) == target and flags & os.O_CREAT:
                self.add_acl(self.home, "everyone allow read,file_inherit,directory_inherit")
            return original_open(path, flags, *args, **kwargs)

        with patch("continuum_memory.security.os.open", side_effect=inherit_before_create):
            with self.assertRaises(MemoryError):
                write_private(target, b"must-not-be-written")
        self.assertEqual(target.read_bytes(), b"")

    def test_metadata_open_refuses_raced_file_substitution(self):
        original_open = os.open
        for kind in ("regular", "symlink", "fifo", "hardlink"):
            with self.subTest(kind=kind):
                source = self.home / (kind + ".cap")
                target = self.home / (kind + ".target")
                displaced = self.home / (kind + ".displaced")
                write_private(source, b"original")
                write_private(target, b"untouched")
                changed = False

                def swap_before_open(path, flags, *args, **kwargs):
                    nonlocal changed
                    if Path(path) == source and not changed:
                        changed = True
                        source.rename(displaced)
                        if kind == "regular":
                            fd = original_open(source, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                            os.close(fd)
                        elif kind == "symlink":
                            source.symlink_to(target)
                        elif kind == "fifo":
                            os.mkfifo(source, 0o600)
                        else:
                            os.link(target, source)
                    return original_open(path, flags, *args, **kwargs)

                with patch("continuum_memory.security.os.open", side_effect=swap_before_open):
                    with self.assertRaises(MemoryError):
                        ensure_private_regular(source)
                self.assertEqual(target.read_bytes(), b"untouched")

    def test_database_and_every_existing_sidecar_acl_refused_before_sqlite(self):
        Store.bootstrap(self.home, [{"name": "mac", "path_hint": "/synthetic", "providers": ["codex"]}])
        database = paths(self.home)["db"]
        for suffix in ("", "-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                target = Path(str(database) + suffix)
                created = not target.exists()
                if created:
                    write_private(target, b"synthetic-sidecar")
                before = target.read_bytes()
                self.add_acl(target)
                try:
                    with patch("continuum_memory.storage.sqlite3.connect") as connect:
                        with self.assertRaises(MemoryError) as caught:
                            _connect(database)
                        self.assertEqual(caught.exception.code, "unsafe_permissions")
                        connect.assert_not_called()
                    self.assertEqual(target.read_bytes(), before)
                finally:
                    subprocess.run(["/bin/chmod", "-N", str(target)], check=True, capture_output=True, timeout=5)
                    if created:
                        target.unlink()


if __name__ == "__main__":
    unittest.main()
