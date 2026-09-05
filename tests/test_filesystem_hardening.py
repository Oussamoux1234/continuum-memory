import os
import tempfile
import unittest
from pathlib import Path

from continuum_memory.client import DaemonClient
from continuum_memory.daemon import serve
from continuum_memory.errors import MemoryError
from continuum_memory.storage import Store, load_capability, paths


PROJECTS = [
    {"name": "alpha", "path_hint": "/fixture/alpha", "providers": ["codex"]},
]


class FilesystemHardeningTest(unittest.TestCase):
    def test_bootstrap_rejects_symlink_and_permissive_directory(self):
        with tempfile.TemporaryDirectory(prefix="continuum-fs-parent-") as temporary:
            parent = Path(temporary)
            target = parent / "target"
            target.mkdir(mode=0o700)
            linked = parent / "linked"
            linked.symlink_to(target, target_is_directory=True)
            with self.assertRaises(MemoryError) as symlink:
                Store.bootstrap(linked, PROJECTS)
            self.assertEqual(symlink.exception.code, "unsafe_directory")

            parent_target = parent / "parent-target"
            parent_target.mkdir(mode=0o700)
            linked_parent = parent / "linked-parent"
            linked_parent.symlink_to(parent_target, target_is_directory=True)
            with self.assertRaises(MemoryError) as ancestor:
                Store.bootstrap(linked_parent / "nested-vault", PROJECTS)
            self.assertEqual(ancestor.exception.code, "unsafe_directory")

            permissive = parent / "permissive"
            permissive.mkdir(mode=0o755)
            with self.assertRaises(MemoryError) as permissions:
                Store.bootstrap(permissive, PROJECTS)
            self.assertEqual(permissions.exception.code, "unsafe_permissions")

    def test_capabilities_reject_symlinks_hardlinks_and_open_modes(self):
        with tempfile.TemporaryDirectory(prefix="continuum-fs-cap-") as temporary:
            data_dir = Path(temporary)
            Store.bootstrap(data_dir, PROJECTS)
            capability = paths(data_dir)["control"]
            symlink = data_dir / "linked.cap"
            symlink.symlink_to(capability.name)
            with self.assertRaises(MemoryError) as linked:
                load_capability(symlink)
            self.assertEqual(linked.exception.code, "unsafe_file")

            hardlink = data_dir / "hard.cap"
            os.link(str(capability), str(hardlink))
            with self.assertRaises(MemoryError) as hardlinked:
                load_capability(capability)
            self.assertEqual(hardlinked.exception.code, "unsafe_file")
            hardlink.unlink()

            os.chmod(str(capability), 0o644)
            with self.assertRaises(MemoryError) as permissions:
                load_capability(capability)
            self.assertEqual(permissions.exception.code, "unsafe_permissions")
            os.chmod(str(capability), 0o600)
            self.assertEqual(load_capability(capability)["provider"], "user_control")

    def test_database_rejects_symlinks_hardlinks_and_open_modes(self):
        with tempfile.TemporaryDirectory(prefix="continuum-fs-db-") as temporary:
            data_dir = Path(temporary)
            Store.bootstrap(data_dir, PROJECTS)
            database = paths(data_dir)["db"]

            hardlink = data_dir / "database-hardlink"
            os.link(str(database), str(hardlink))
            with self.assertRaises(MemoryError) as hardlinked:
                Store(data_dir)
            self.assertEqual(hardlinked.exception.code, "unsafe_file")
            hardlink.unlink()

            os.chmod(str(database), 0o644)
            with self.assertRaises(MemoryError) as permissions:
                Store(data_dir)
            self.assertEqual(permissions.exception.code, "unsafe_permissions")
            os.chmod(str(database), 0o600)

            real_database = data_dir / "database-real"
            database.rename(real_database)
            database.symlink_to(real_database.name)
            with self.assertRaises(MemoryError) as linked:
                Store(data_dir)
            self.assertEqual(linked.exception.code, "unsafe_file")

    def test_storage_key_rejects_missing_symlink_hardlink_and_open_modes(self):
        with tempfile.TemporaryDirectory(prefix="continuum-fs-key-") as temporary:
            data_dir = Path(temporary)
            Store.bootstrap(data_dir, PROJECTS)
            storage_key = paths(data_dir)["storage_key"]
            original_key = storage_key.read_bytes()

            storage_key.unlink()
            with self.assertRaises(MemoryError) as missing:
                Store(data_dir)
            self.assertEqual(missing.exception.code, "storage_key_unavailable")

            storage_key.write_bytes(original_key)
            os.chmod(str(storage_key), 0o600)
            hardlink = data_dir / "storage-key-hardlink"
            os.link(str(storage_key), str(hardlink))
            with self.assertRaises(MemoryError) as hardlinked:
                Store(data_dir)
            self.assertEqual(hardlinked.exception.code, "storage_key_unavailable")
            hardlink.unlink()

            os.chmod(str(storage_key), 0o644)
            with self.assertRaises(MemoryError) as permissions:
                Store(data_dir)
            self.assertEqual(permissions.exception.code, "storage_key_unavailable")
            os.chmod(str(storage_key), 0o600)

            real_key = data_dir / "storage-key-real"
            storage_key.rename(real_key)
            storage_key.symlink_to(real_key.name)
            with self.assertRaises(MemoryError) as linked:
                Store(data_dir)
            self.assertEqual(linked.exception.code, "storage_key_unavailable")

    def test_client_and_daemon_reject_socket_symlink(self):
        with tempfile.TemporaryDirectory(prefix="continuum-fs-socket-") as temporary:
            data_dir = Path(temporary)
            Store.bootstrap(data_dir, PROJECTS)
            socket_path = paths(data_dir)["socket"]
            socket_path.symlink_to(paths(data_dir)["db"].name)
            client = DaemonClient(data_dir, paths(data_dir)["control"])
            with self.assertRaises(MemoryError) as client_error:
                client.call("status", {})
            self.assertEqual(client_error.exception.code, "unsafe_socket")
            with self.assertRaises(MemoryError) as daemon_error:
                serve(data_dir)
            self.assertEqual(daemon_error.exception.code, "unsafe_socket")


if __name__ == "__main__":
    unittest.main()
