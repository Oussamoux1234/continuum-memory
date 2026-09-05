import hashlib
import os
import sqlite3 as plaintext_sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from continuum_memory import storage
from continuum_memory.errors import MemoryError
from continuum_memory.security import write_private
from continuum_memory.storage import STORAGE_MODE, Store, paths
from fixtures.harness import EphemeralHarness


PROJECTS = [
    {"name": "encrypted", "path_hint": "/fixture/encrypted", "providers": ["codex"]},
]
CANARY = "CONTINUUM_SQLCIPHER_CANARY_7e65b1"


class EncryptedStorageTest(unittest.TestCase):
    def test_bootstrap_encrypts_database_and_correct_key_reopens(self):
        with tempfile.TemporaryDirectory(prefix="continuum-encrypted-") as temporary:
            data_dir = Path(temporary)
            result = Store.bootstrap(data_dir, PROJECTS)
            self.assertEqual(result["storage_mode"], STORAGE_MODE)
            storage_key = paths(data_dir)["storage_key"].read_bytes()
            self.assertEqual(len(storage_key), 32)
            self.assertNotIn(storage_key.hex(), str(result))
            self.assertEqual(paths(data_dir)["storage_key"].stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(
                paths(data_dir)["db"].read_bytes()[:16],
                b"SQLite format 3\x00",
            )

            store = Store(data_dir)
            try:
                self.assertEqual(store.storage_mode, STORAGE_MODE)
                self.assertEqual(str(store.connection.execute("PRAGMA cipher_status").fetchone()[0]), "1")
                self.assertEqual(
                    store.connection.execute(
                        "SELECT value FROM metadata WHERE key='storage_mode'"
                    ).fetchone()[0],
                    STORAGE_MODE,
                )
            finally:
                store.close()

    def test_missing_malformed_and_wrong_keys_fail_closed(self):
        for case in ("missing", "malformed", "wrong"):
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory(prefix="continuum-key-failure-") as temporary:
                    data_dir = Path(temporary)
                    Store.bootstrap(data_dir, PROJECTS)
                    key_path = paths(data_dir)["storage_key"]
                    if case == "missing":
                        key_path.unlink()
                        expected = "storage_key_unavailable"
                    elif case == "malformed":
                        key_path.write_bytes(b"too-short")
                        expected = "storage_key_unavailable"
                    else:
                        key_path.write_bytes(os.urandom(32))
                        expected = "storage_key_invalid"
                    with self.assertRaises(MemoryError) as error:
                        Store(data_dir)
                    self.assertEqual(error.exception.code, expected)
                    self.assertNotIn(CANARY, str(error.exception.as_dict()))

    def test_plaintext_vault_is_rejected_without_mutation(self):
        with tempfile.TemporaryDirectory(prefix="continuum-plaintext-reject-") as temporary:
            data_dir = Path(temporary)
            database = paths(data_dir)["db"]
            connection = plaintext_sqlite3.connect(str(database))
            try:
                connection.execute("CREATE TABLE legacy(value TEXT)")
                connection.execute("INSERT INTO legacy(value) VALUES (?)", (CANARY,))
                connection.commit()
            finally:
                connection.close()
            os.chmod(str(database), 0o600)
            write_private(paths(data_dir)["storage_key"], os.urandom(32))
            write_private(paths(data_dir)["audit_key"], os.urandom(32))
            before = hashlib.sha256(database.read_bytes()).digest()

            with self.assertRaises(MemoryError) as error:
                Store(data_dir)
            self.assertEqual(error.exception.code, "storage_key_invalid")
            self.assertEqual(hashlib.sha256(database.read_bytes()).digest(), before)
            self.assertEqual(database.read_bytes()[:16], b"SQLite format 3\x00")

    def test_runtime_unavailability_never_falls_back_to_plaintext(self):
        with tempfile.TemporaryDirectory(prefix="continuum-no-sqlcipher-") as temporary:
            data_dir = Path(temporary)
            Store.bootstrap(data_dir, PROJECTS)
            before = hashlib.sha256(paths(data_dir)["db"].read_bytes()).digest()
            with mock.patch.object(storage, "sqlite3", None):
                with self.assertRaises(MemoryError) as error:
                    Store(data_dir)
            self.assertEqual(error.exception.code, "sqlcipher_unavailable")
            self.assertEqual(hashlib.sha256(paths(data_dir)["db"].read_bytes()).digest(), before)

            uninitialized = data_dir / "new-vault"
            with mock.patch.object(storage, "sqlite3", None):
                with self.assertRaises(MemoryError) as bootstrap_error:
                    Store.bootstrap(uninitialized, PROJECTS)
            self.assertEqual(bootstrap_error.exception.code, "sqlcipher_unavailable")
            self.assertFalse(uninitialized.exists())

    def test_storage_key_directory_entry_is_synced_before_database_creation(self):
        with tempfile.TemporaryDirectory(prefix="continuum-key-durability-") as temporary:
            data_dir = Path(temporary)
            events = []
            original_write = storage.write_private
            original_sync = storage._sync_private_directory
            original_connect = storage._connect

            def tracked_write(path, data):
                events.append("write:%s" % path.name)
                return original_write(path, data)

            def tracked_sync(path):
                events.append("sync:%s" % path.name)
                return original_sync(path)

            def tracked_connect(*args, **kwargs):
                events.append("connect")
                return original_connect(*args, **kwargs)

            with mock.patch.object(storage, "write_private", side_effect=tracked_write):
                with mock.patch.object(
                    storage,
                    "_sync_private_directory",
                    side_effect=tracked_sync,
                ):
                    with mock.patch.object(storage, "_connect", side_effect=tracked_connect):
                        Store.bootstrap(data_dir, PROJECTS)

            key_write = events.index("write:storage.key")
            key_directory_sync = events.index("sync:%s" % data_dir.name)
            database_write = events.index("write:continuum.db")
            database_connect = events.index("connect")
            self.assertLess(key_write, key_directory_sync)
            self.assertLess(key_directory_sync, database_write)
            self.assertLess(database_write, database_connect)

    def test_incompatible_encrypted_vault_is_rejected_without_mutation(self):
        for mismatch, expected_error in (
            ("schema", "schema_mismatch"),
            ("storage_mode", "storage_mode_mismatch"),
        ):
            with self.subTest(mismatch=mismatch):
                with tempfile.TemporaryDirectory(
                    prefix="continuum-incompatible-reject-"
                ) as temporary:
                    data_dir = Path(temporary)
                    Store.bootstrap(data_dir, PROJECTS)
                    database = paths(data_dir)["db"]
                    storage_key = paths(data_dir)["storage_key"].read_bytes()
                    store = Store(data_dir)
                    store.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    store.connection.execute("PRAGMA journal_mode=DELETE")
                    if mismatch == "schema":
                        store.connection.execute("PRAGMA user_version=999")
                    else:
                        store.connection.execute(
                            "UPDATE metadata SET value='future-mode' "
                            "WHERE key='storage_mode'"
                        )
                    store.close()
                    before_bytes = database.read_bytes()
                    before_sidecars = {
                        path.name: path.read_bytes()
                        for path in data_dir.glob("continuum.db-*")
                        if path.is_file()
                    }

                    with self.assertRaises(MemoryError) as error:
                        Store(data_dir)
                    self.assertEqual(error.exception.code, expected_error)
                    self.assertEqual(database.read_bytes(), before_bytes)
                    self.assertEqual(
                        {
                            path.name: path.read_bytes()
                            for path in data_dir.glob("continuum.db-*")
                            if path.is_file()
                        },
                        before_sidecars,
                    )

                    validation = storage._connect(database, storage_key)
                    try:
                        self.assertEqual(
                            str(
                                validation.execute("PRAGMA journal_mode").fetchone()[0]
                            ).lower(),
                            "delete",
                        )
                    finally:
                        validation.close()
                    self.assertEqual(database.read_bytes(), before_bytes)

    def test_every_required_connection_setting_is_read_back_and_enforced(self):
        with tempfile.TemporaryDirectory(prefix="continuum-pragma-readback-") as temporary:
            data_dir = Path(temporary)
            Store.bootstrap(data_dir, PROJECTS)
            store = Store(data_dir)
            try:
                expected = dict(storage.REQUIRED_CONNECTION_SETTINGS, journal_mode="wal")
                self.assertEqual(
                    storage._read_connection_settings(
                        store.connection,
                        include_journal=True,
                    ),
                    expected,
                )
                original_readback = storage._read_connection_settings
                for setting in expected:
                    with self.subTest(setting=setting):
                        def mismatched_readback(connection, include_journal=False):
                            actual = original_readback(connection, include_journal)
                            if setting in actual:
                                actual[setting] = -1
                            return actual

                        with mock.patch.object(
                            storage,
                            "_read_connection_settings",
                            side_effect=mismatched_readback,
                        ):
                            with self.assertRaises(MemoryError) as error:
                                storage._apply_connection_hardening(
                                    store.connection,
                                    paths(data_dir)["db"],
                                )
                        self.assertEqual(error.exception.code, "storage_hardening_failed")
            finally:
                store.close()

    def test_directory_sync_uses_a_real_directory_descriptor(self):
        with tempfile.TemporaryDirectory(prefix="continuum-directory-sync-") as temporary:
            directory = Path(temporary)
            with mock.patch.object(storage.os, "fsync", wraps=os.fsync) as fsync:
                storage._sync_private_directory(directory)
            self.assertEqual(fsync.call_count, 1)
            descriptor = fsync.call_args.args[0]
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            self.assertTrue(stat.S_ISDIR(directory.stat().st_mode))

            with mock.patch.object(storage.os, "fsync", side_effect=OSError(str(directory))):
                with self.assertRaises(MemoryError) as error:
                    storage._sync_private_directory(directory)
            self.assertEqual(error.exception.code, "storage_key_unavailable")
            self.assertNotIn(str(directory), str(error.exception.as_dict()))

    def test_canary_is_absent_from_database_wal_shm_and_temp_artifacts(self):
        with tempfile.TemporaryDirectory(prefix="continuum-sqlite-temp-") as sqlite_temp:
            with mock.patch.dict(os.environ, {"SQLITE_TMPDIR": sqlite_temp}):
                with EphemeralHarness() as harness:
                    project = harness.projects["alpha"]["id"]
                    remembered = harness.approve(
                        {
                            "operation": "remember",
                            "project": project,
                            "subject": CANARY,
                            "claim": "Encrypted claim %s" % CANARY,
                            "evidence": "Encrypted evidence %s" % CANARY,
                            "evidence_locator": "fixture:encrypted-canary",
                            "classification": "internal",
                            "retention": "forever",
                            "disclosure": ["codex"],
                            "valid_precision": "unknown",
                        }
                    )["result"]
                    client = harness.mcp("alpha", "codex")
                    result = client.call("memory_search", {"query": CANARY, "limit": 5})
                    self.assertEqual(result["cards"][0]["version_id"], remembered["assertion_id"])
                    status = client.call("memory_status", {})
                    self.assertEqual(status["storage_mode"], STORAGE_MODE)

                    inspection_store = Store(harness.data_dir)
                    try:
                        self.assertEqual(
                            inspection_store.connection.execute("PRAGMA temp_store").fetchone()[0],
                            2,
                        )
                        inspection_store.connection.execute(
                            "CREATE TEMP TABLE encryption_temp_canary(value TEXT)"
                        )
                        inspection_store.connection.execute(
                            "INSERT INTO encryption_temp_canary(value) VALUES (?)", (CANARY,)
                        )
                        artifacts = list(harness.data_dir.glob("continuum.db*"))
                        artifacts.extend(path for path in Path(sqlite_temp).rglob("*") if path.is_file())
                        self.assertTrue(any(path.name.endswith("-wal") for path in artifacts))
                        for artifact in artifacts:
                            self.assertNotIn(CANARY.encode("utf-8"), artifact.read_bytes(), artifact)
                    finally:
                        inspection_store.close()

    def test_committed_wal_recovers_after_unclean_process_exit(self):
        with tempfile.TemporaryDirectory(prefix="continuum-crash-recovery-") as temporary:
            data_dir = Path(temporary)
            Store.bootstrap(data_dir, PROJECTS)
            root = Path(__file__).resolve().parents[1]
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(root / "src")
            script = (
                "import os,sys; from pathlib import Path; "
                "from continuum_memory.storage import Store; "
                "s=Store(Path(sys.argv[1])); "
                "s.connection.execute(\"BEGIN IMMEDIATE\"); "
                "s.connection.execute(\"INSERT INTO metadata(key,value) VALUES ('crash_canary',?)\", "
                "(sys.argv[2],)); s.connection.commit(); os._exit(0)"
            )
            completed = subprocess.run(
                [sys.executable, "-c", script, str(data_dir), CANARY],
                env=environment,
                check=False,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 0)

            store = Store(data_dir)
            try:
                self.assertEqual(
                    store.connection.execute(
                        "SELECT value FROM metadata WHERE key='crash_canary'"
                    ).fetchone()[0],
                    CANARY,
                )
                self.assertEqual(store.connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(list(store.connection.execute("PRAGMA cipher_integrity_check")), [])
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
