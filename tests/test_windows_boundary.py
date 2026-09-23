"""Native filesystem evidence only: these tests do not enable the Windows runtime."""

import ctypes
import os
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from continuum_memory.errors import MemoryError
from continuum_memory.windows_boundary import (
    BOOL, DWORD, HANDLE, LPWSTR, POINTER, WindowsBoundary,
    _Acl, _Ace, _FileInfo, _SecurityAttributes, local_path,
)


class WindowsPathTest(unittest.TestCase):
    def test_unambiguous_drive_paths_only(self):
        self.assertEqual(local_path("c:/vault/key"), "C:\\vault\\key")
        for path in ("vault", "C:key", "C:\\", "C:\\vault\\", "\\\\server\\share\\key",
                     "\\\\?\\C:\\vault", "\\\\.\\pipe\\memory", "C:\\a\\..\\key", "C:\\a\\.\\key",
                     "C:\\a\\\\key", "C:\\a\\key:stream", "C:\\a\\key.", "C:\\a\\key ",
                     "C:\\a\\NUL", "C:\\a\\con.txt", "C:\\a\\COM¹", "C:\\a\\LPT9.log",
                     "C:\\a\\ke\x00y", "C:\\a\\ke*y", "C:\\a\\\ud800", "C:\\" + "x" * 245):
            with self.subTest(path=ascii(path)), self.assertRaises(MemoryError):
                local_path(path)

    @unittest.skipIf(os.name == "nt", "Non-Windows refusal")
    def test_other_platforms_are_explicitly_refused(self):
        with self.assertRaises(MemoryError) as error:
            WindowsBoundary()
        self.assertEqual(error.exception.code, "unsupported_platform")


@unittest.skipUnless(os.name == "nt", "Native Windows boundary evidence requires Windows")
class NativeWindowsBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-win-boundary-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.boundary = WindowsBoundary()
        self.private = self.root / "private"
        self.boundary.create_directory(self.private)
        self.key = self.private / "key"
        self.boundary.write_new(self.key, b"synthetic-fixture")

    @contextmanager
    def attributes(self, sddl):
        descriptor = POINTER()
        function = self.boundary.security.ConvertStringSecurityDescriptorToSecurityDescriptorW
        self.assertTrue(function(sddl, 1, ctypes.byref(descriptor), None))
        try:
            yield _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        finally:
            self.boundary.kernel.LocalFree(descriptor)

    def directory_with_acl(self, name, sddl):
        path = self.root / name
        with self.attributes(sddl) as attributes:
            self.assertTrue(self.boundary.kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)),
                            "Native security fixture creation failed: %s" % ctypes.get_last_error())
        return path

    def test_win64_abi_and_roundtrip(self):
        self.assertEqual(ctypes.sizeof(HANDLE), 8, "This evidence matrix requires x64 Python")
        self.assertEqual(ctypes.sizeof(_SecurityAttributes), 24)
        self.assertEqual(_SecurityAttributes.descriptor.offset, 8)
        self.assertEqual(ctypes.sizeof(_FileInfo), 52)
        self.assertEqual(ctypes.sizeof(_Acl), 8)
        self.assertEqual(ctypes.sizeof(_Ace), 8)
        first = self.boundary.inspect(self.key)
        self.assertEqual(first, self.boundary.inspect(self.key))
        self.assertEqual(self.boundary.read(self.key), b"synthetic-fixture")

    def test_refuses_existing_objects_without_changing_contents(self):
        with self.assertRaises(MemoryError):
            self.boundary.write_new(self.key, b"replacement")
        with self.assertRaises(MemoryError):
            self.boundary.create_directory(self.private)
        self.assertEqual(self.key.read_bytes(), b"synthetic-fixture")

    def test_read_bounds_and_wrong_types(self):
        with self.assertRaises(MemoryError) as error:
            self.boundary.read(self.key, maximum=3)
        self.assertEqual(error.exception.code, "unsafe_file")
        with self.assertRaises(MemoryError):
            self.boundary.inspect(self.private)
        with self.assertRaises(MemoryError):
            self.boundary.inspect(self.key, directory=True)
        for bound in (-1, 65537, True):
            with self.assertRaises(MemoryError):
                self.boundary.read(self.key, bound)

    def test_acl_rejections(self):
        sid = self.boundary.sid
        cases = {
            "broad": "O:%sD:P(A;;FA;;;%s)(A;;FR;;;WD)" % (sid, sid),
            "null": "O:%sD:NO_ACCESS_CONTROL" % sid,
            "unprotected": "O:%sD:(A;;FA;;;%s)" % (sid, sid),
            "inheritable": "O:%sD:P(A;OICI;FA;;;%s)" % (sid, sid),
            "insufficient": "O:%sD:P(A;;FR;;;%s)" % (sid, sid),
            "different_principal": "O:%sD:P(A;;FA;;;BA)" % sid,
        }
        for name, sddl in cases.items():
            with self.subTest(name=name):
                path = self.directory_with_acl(name, sddl)
                with self.assertRaises(MemoryError) as error:
                    self.boundary.inspect(path, directory=True)
                self.assertEqual(error.exception.code, "unsafe_permissions")

    def test_wrong_owner_is_rejected_on_native_admin_fixture(self):
        # GitHub's x64 Windows runner permits Administrators ownership on a
        # synthetic directory. Failure to create it FAILS evidence, never skips.
        path = self.directory_with_acl("wrong-owner", "O:BAD:P(A;;FA;;;%s)" % self.boundary.sid)
        with self.assertRaises(MemoryError) as error:
            self.boundary.inspect(path, directory=True)
        self.assertEqual(error.exception.code, "unsafe_owner")

    def test_hardlinks_are_rejected(self):
        alias = self.private / "alias"
        os.link(self.key, alias)
        for path in (self.key, alias):
            with self.assertRaises(MemoryError) as error:
                self.boundary.read(path)
            self.assertEqual(error.exception.code, "unsafe_file")
        alias.unlink()
        self.assertEqual(self.boundary.read(self.key), b"synthetic-fixture")

    def test_junction_leaf_and_ancestor_rejected(self):
        junction = self.root / "junction"
        result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(self.private)],
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, "Native junction fixture creation failed")
        self.addCleanup(junction.rmdir)
        for path, directory in ((junction, True), (junction / "key", False)):
            with self.assertRaises(MemoryError) as error:
                self.boundary.inspect(path, directory=directory)
            self.assertEqual(error.exception.code, "unsafe_reparse_point")

    def test_symlink_leaf_rejected(self):
        link = self.private / "symlink"
        # No skip: native CI must supply the documented symlink fixture privilege.
        link.symlink_to(self.key)
        with self.assertRaises(MemoryError) as error:
            self.boundary.read(link)
        self.assertEqual(error.exception.code, "unsafe_reparse_point")

    def test_leaf_and_ancestor_cannot_be_replaced_while_held(self):
        with self.boundary.open_private(self.key):
            with self.assertRaises(OSError):
                self.key.rename(self.private / "moved-key")
            with self.assertRaises(OSError):
                self.private.rename(self.root / "moved-parent")
        # Closing the context releases both handles, not just the leaf.
        self.key.rename(self.private / "moved-key")
        self.private.rename(self.root / "moved-parent")

    def test_context_error_releases_all_handles(self):
        with self.assertRaisesRegex(RuntimeError, "fixture"):
            with self.boundary.open_private(self.key):
                raise RuntimeError("fixture")
        self.private.rename(self.root / "released")

    def test_repeated_failures_do_not_leak_handles(self):
        count = self.boundary.kernel.GetProcessHandleCount
        count.argtypes, count.restype = [HANDLE, POINTER], BOOL
        before, after = DWORD(), DWORD()
        self.assertTrue(count(self.boundary.kernel.GetCurrentProcess(), ctypes.byref(before)))
        for _ in range(100):
            with self.assertRaises(MemoryError):
                self.boundary.read(self.private / "missing")
        self.assertTrue(count(self.boundary.kernel.GetCurrentProcess(), ctypes.byref(after)))
        self.assertEqual(after.value, before.value)


if __name__ == "__main__":
    unittest.main()
