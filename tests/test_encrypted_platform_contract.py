"""Prepared fail-closed contracts; no Windows encrypted runtime is implemented."""

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from continuum_memory import storage
from continuum_memory.errors import MemoryError


class EncryptedPlatformContractTest(unittest.TestCase):
    def test_windows_refuses_before_files_keys_or_backend_are_accessed(self):
        home = Path("unopened-synthetic-vault")
        operations = (
            lambda: storage.Store(home),
            lambda: storage.Store._open_during_rotation(home),
            lambda: storage.Store.bootstrap(home, []),
            lambda: storage._connect(home / "continuum.db", b"x" * 32),
            storage._require_sqlcipher_runtime,
        )
        for operation in operations:
            with self.subTest(operation=operation), \
                    patch.object(storage, "os", SimpleNamespace(name="nt")), \
                    patch.object(storage, "ensure_private_directory") as directory, \
                    patch.object(storage, "_read_storage_key") as key, \
                    patch.object(storage, "require_no_pending_rotation") as custody, \
                    patch.object(storage, "sqlite3") as backend, \
                    patch.object(storage, "metadata") as metadata:
                with self.assertRaises(MemoryError) as caught:
                    operation()
                self.assertEqual(caught.exception.code, "unsupported_platform")
                directory.assert_not_called()
                key.assert_not_called()
                custody.assert_not_called()
                backend.connect.assert_not_called()
                metadata.version.assert_not_called()

    def test_read_only_observer_cannot_request_write_hardening(self):
        with patch.object(storage, "os", SimpleNamespace(name="posix")), \
                patch.object(storage, "_validate_database_files") as files, \
                patch.object(storage, "_require_sqlcipher_runtime") as runtime:
            with self.assertRaises(MemoryError) as caught:
                storage._connect(Path("unopened.db"), b"x" * 32, apply_hardening=True, read_only=True)
            self.assertEqual(caught.exception.code, "storage_validation_failed")
            files.assert_not_called()
            runtime.assert_not_called()
