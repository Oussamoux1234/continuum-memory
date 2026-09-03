import hashlib
import os
import sqlite3 as plaintext_sqlite3
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
