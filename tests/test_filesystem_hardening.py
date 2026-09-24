import os
import tempfile
import unittest
from pathlib import Path

from continuum_memory.client import DaemonClient
from continuum_memory.daemon import serve
from continuum_memory.errors import MemoryError
from continuum_memory.security import create_private_directory
from continuum_memory.storage import Store, load_capability, paths
from fixtures.harness import private_test_home
from fixtures.windows_acl import set_fixture_acl


def set_permissions(path, private):
    if os.name == "nt":
        set_fixture_acl(path, broad=not private)
    else:
        os.chmod(path, 0o600 if private else 0o644)


PROJECTS = [
    {"name": "alpha", "path_hint": "/fixture/alpha", "providers": ["codex"]},
]


class FilesystemHardeningTest(unittest.TestCase):
    def test_bootstrap_rejects_symlink_and_permissive_directory(self):
        with tempfile.TemporaryDirectory(prefix="continuum-fs-parent-") as temporary:
            parent = Path(temporary)
            target = parent / "target"
            create_private_directory(target)
            linked = parent / "linked"
            linked.symlink_to(target, target_is_directory=True)
            with self.assertRaises(MemoryError) as symlink:
                Store.bootstrap(linked, PROJECTS)
            self.assertEqual(symlink.exception.code, "unsafe_reparse_point" if os.name == "nt" else "unsafe_directory")

            parent_target = parent / "parent-target"
            create_private_directory(parent_target)
            linked_parent = parent / "linked-parent"
            linked_parent.symlink_to(parent_target, target_is_directory=True)
            with self.assertRaises(MemoryError) as ancestor:
                Store.bootstrap(linked_parent / "nested-vault", PROJECTS)
            self.assertEqual(ancestor.exception.code, "unsafe_reparse_point" if os.name == "nt" else "unsafe_directory")

            permissive = parent / "permissive"
            permissive.mkdir(mode=0o755)
            with self.assertRaises(MemoryError) as permissions:
                Store.bootstrap(permissive, PROJECTS)
            self.assertEqual(permissions.exception.code, "unsafe_permissions")

    def test_capabilities_reject_symlinks_hardlinks_and_open_modes(self):
        with tempfile.TemporaryDirectory(prefix="continuum-fs-cap-") as temporary:
            data_dir = private_test_home(temporary)
            Store.bootstrap(data_dir, PROJECTS)
            capability = paths(data_dir)["control"]
            symlink = data_dir / "linked.cap"
            symlink.symlink_to(capability.name)
            with self.assertRaises(MemoryError) as linked:
                load_capability(symlink)
            self.assertEqual(linked.exception.code, "unsafe_reparse_point" if os.name == "nt" else "unsafe_file")

            hardlink = data_dir / "hard.cap"
            os.link(str(capability), str(hardlink))
            with self.assertRaises(MemoryError) as hardlinked:
                load_capability(capability)
            self.assertEqual(hardlinked.exception.code, "unsafe_file")
            hardlink.unlink()

            set_permissions(capability, False)
            with self.assertRaises(MemoryError) as permissions:
                load_capability(capability)
            self.assertEqual(permissions.exception.code, "unsafe_permissions")
            set_permissions(capability, True)
            self.assertEqual(load_capability(capability)["provider"], "user_control")

    def test_database_rejects_symlinks_hardlinks_and_open_modes(self):
        with tempfile.TemporaryDirectory(prefix="continuum-fs-db-") as temporary:
            data_dir = private_test_home(temporary)
            Store.bootstrap(data_dir, PROJECTS)
            database = paths(data_dir)["db"]

            hardlink = data_dir / "database-hardlink"
            os.link(str(database), str(hardlink))
            with self.assertRaises(MemoryError) as hardlinked:
                Store(data_dir)
            self.assertEqual(hardlinked.exception.code, "unsafe_file")
            hardlink.unlink()

            set_permissions(database, False)
            with self.assertRaises(MemoryError) as permissions:
                Store(data_dir)
            self.assertEqual(permissions.exception.code, "unsafe_permissions")
            set_permissions(database, True)

            real_database = data_dir / "database-real"
            database.rename(real_database)
            database.symlink_to(real_database.name)
            with self.assertRaises(MemoryError) as linked:
                Store(data_dir)
            self.assertEqual(linked.exception.code, "unsafe_reparse_point" if os.name == "nt" else "unsafe_file")

    @unittest.skipIf(os.name == "nt", "Unix socket path; native pipe/binding rejection is tested separately")
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
