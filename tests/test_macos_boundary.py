"""Native APFS fixtures only; no Keychain, signing, sudo, or human approval."""

import hashlib
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum_memory.errors import MemoryError
from continuum_memory.security import read_private, replace_private, write_private
from continuum_memory.storage import Store, paths


@unittest.skipUnless(sys.platform == "darwin", "native macOS/APFS acceptance slice")
class MacOSBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cm-mac-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)

    def test_fixture_volume_is_really_apfs(self):
        result = subprocess.run(["/bin/df", "-P", str(self.home)], check=True, capture_output=True, timeout=10)
        device = result.stdout.decode().splitlines()[-1].split()[0]
        self.assertTrue(device.startswith("/dev/"), "fixture device is not a local volume")
        result = subprocess.run(["/usr/sbin/diskutil", "info", "-plist", device], check=True, capture_output=True, timeout=15)
        info = plistlib.loads(result.stdout)
        self.assertEqual(info.get("FilesystemType"), "apfs")
        self.assertIs(info.get("GlobalPermissionsEnabled"), True)
        print("macOS fixture filesystem: apfs; ownership permissions enabled", flush=True)

    def test_database_sidecar_capability_and_atomic_temporary_modes(self):
        Store.bootstrap(self.home, [{"name": "mac", "path_hint": "/fixture/mac", "providers": ["codex"]}])
        store = Store(self.home)
        try:
            database = paths(self.home)["db"]
            for path in (database, Path(str(database) + "-wal"), Path(str(database) + "-shm"),
                         paths(self.home)["control"], paths(self.home)["audit_key"]):
                info = path.stat()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(info.st_mode & 0o777, 0o600)
                self.assertEqual(info.st_uid, os.getuid())
                self.assertEqual(info.st_nlink, 1)
        finally:
            store.close()
        target = self.home / "synthetic.cap"
        write_private(target, b"old")
        original_replace = os.replace
        observed = []
        def inspect_staging(source, destination):
            info = Path(source).stat()
            self.assertEqual(Path(source).parent, self.home)
            self.assertEqual(info.st_mode & 0o777, 0o600)
            self.assertEqual(info.st_uid, os.getuid())
            self.assertEqual(info.st_nlink, 1)
            observed.append(source)
            return original_replace(source, destination)
        with patch("continuum_memory.security.os.replace", side_effect=inspect_staging):
            replace_private(target, b"new")
        self.assertEqual(read_private(target), b"new")
        self.assertEqual(len(observed), 1)
        self.assertFalse(list(self.home.glob(".*.tmp")))

    def test_raced_symlink_fifo_and_hardlink_reads_are_rejected(self):
        original_open = os.open
        for kind in ("symlink", "fifo", "hardlink"):
            with self.subTest(kind=kind):
                source = self.home / (kind + ".cap")
                target = self.home / (kind + ".target")
                write_private(source, b"synthetic-original")
                write_private(target, b"synthetic-target")
                def replace_before_open(path, flags, *args, **kwargs):
                    if Path(path) == source:
                        source.unlink()
                        if kind == "symlink":
                            source.symlink_to(target)
                        elif kind == "fifo":
                            os.mkfifo(source, 0o600)
                        else:
                            os.link(target, source)
                    return original_open(path, flags, *args, **kwargs)
                with patch("continuum_memory.security.os.open", side_effect=replace_before_open):
                    with self.assertRaises(MemoryError) as caught:
                        read_private(source)
                self.assertEqual(caught.exception.code, "unsafe_file")
                self.assertEqual(target.read_bytes(), b"synthetic-target")

    def test_same_uid_child_can_read_prototype_audit_key_is_an_explicit_limit(self):
        # Prove the unresolved boundary honestly: same-UID agent processes are
        # not isolated from owner-only prototype HMAC keys by Unix mode bits.
        Store.bootstrap(self.home, [{"name": "mac", "path_hint": "/fixture/mac", "providers": ["codex"]}])
        key = paths(self.home)["audit_key"]
        expected = hashlib.sha256(key.read_bytes()).hexdigest()
        result = subprocess.run([
            sys.executable, "-I", "-c",
            "import hashlib,pathlib,sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())",
            str(key),
        ], check=True, capture_output=True, timeout=5)
        self.assertEqual(result.stdout.decode().strip(), expected)
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
