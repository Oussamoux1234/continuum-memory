#!/usr/bin/env python3
"""Runtime security and recovery tests for an installed patched SQLCipher wheel."""

import json
import os
import platform
import signal
import sys
import tempfile
from importlib import metadata
from pathlib import Path

CANARY = b"CONTINUUM_PATCHED_SQLCIPHER_CANARY_5c7b41"
RECOVERY_CANARY = b"CONTINUUM_PATCHED_SQLCIPHER_RECOVERY_91e2ab"
KEY = bytes.fromhex("f1" * 32)


def apply_key(connection, key: bytes = KEY) -> None:
    connection.execute("PRAGMA key = \"x'%s'\"" % key.hex())


def open_encrypted(dbapi2, path: Path):
    connection = dbapi2.connect(str(path))
    apply_key(connection)
    connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
    return connection


def require_active_cipher(status: object) -> None:
    if status != "1":
        raise AssertionError("SQLCipher encryption is not active: %r" % (status,))


def assert_no_canary(directory: Path) -> None:
    for path in directory.iterdir():
        if not path.is_file():
            continue
        payload = path.read_bytes()
        for canary in (CANARY, RECOVERY_CANARY):
            if canary in payload:
                raise AssertionError("plaintext canary found in %s" % path.name)


def main() -> int:
    from sqlcipher3 import dbapi2

    module_path = Path(dbapi2.__file__).resolve()
    runtime_prefix = Path(sys.prefix).resolve()
    if runtime_prefix not in module_path.parents:
        raise AssertionError("sqlcipher3 imported outside the isolated runtime environment")
    distribution = metadata.distribution("continuum-sqlcipher3")
    if distribution.version != "0.6.2.post1":
        raise AssertionError("unexpected installed distribution version")
    if dbapi2.sqlite_version != "3.53.4":
        raise AssertionError("unexpected SQLite runtime: %s" % dbapi2.sqlite_version)
    with tempfile.TemporaryDirectory(prefix="continuum-patched-sqlcipher-") as temporary:
        root = Path(temporary)
        os.environ["SQLITE_TMPDIR"] = str(root)
        database = root / "vault.db"
        connection = open_encrypted(dbapi2, database)
        cipher_version = connection.execute("PRAGMA cipher_version").fetchone()[0]
        if cipher_version != "4.18.0 community":
            raise AssertionError("unexpected SQLCipher runtime: %s" % cipher_version)
        require_active_cipher(connection.execute("PRAGMA cipher_status").fetchone()[0])
        options = {row[0] for row in connection.execute("PRAGMA compile_options")}
        if "ENABLE_FTS5" not in options or "TEMP_STORE=2" not in options:
            raise AssertionError("required SQLite compile options are missing")
        journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if str(journal_mode).lower() != "wal":
            raise AssertionError("WAL journal mode was not activated")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA secure_delete=ON")
        if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise AssertionError("FULL synchronous mode was not activated")
        if connection.execute("PRAGMA temp_store").fetchone()[0] != 2:
            raise AssertionError("in-memory temp storage was not activated")
        if connection.execute("PRAGMA secure_delete").fetchone()[0] != 1:
            raise AssertionError("secure_delete was not activated")
        connection.enable_load_extension(False)
        connection.execute("CREATE TABLE memory(body TEXT NOT NULL)")
        connection.execute("CREATE VIRTUAL TABLE memory_fts USING fts5(body)")
        connection.execute("CREATE TEMP TABLE temp_memory(body TEXT NOT NULL)")
        connection.execute("INSERT INTO memory VALUES (?)", (CANARY.decode("ascii"),))
        connection.execute("INSERT INTO memory_fts VALUES (?)", (CANARY.decode("ascii"),))
        connection.execute("INSERT INTO temp_memory VALUES (?)", (CANARY.decode("ascii"),))
        connection.commit()
        if connection.execute("SELECT body FROM memory_fts WHERE memory_fts MATCH 'CANARY'").fetchone()[0].encode() != CANARY:
            raise AssertionError("FTS5 encrypted content did not round-trip")
        if database.read_bytes().startswith(b"SQLite format 3\x00"):
            raise AssertionError("database has a plaintext SQLite header")
        wal = database.with_name(database.name + "-wal")
        if not wal.is_file() or wal.stat().st_size == 0:
            raise AssertionError("encrypted WAL evidence is missing")
        assert_no_canary(root)
        connection.close()

        missing_key = dbapi2.connect(str(database))
        try:
            try:
                missing_key.execute("SELECT count(*) FROM sqlite_master").fetchone()
            except dbapi2.DatabaseError:
                pass
            else:
                raise AssertionError("database opened without a key")
        finally:
            missing_key.close()

        wrong_key = dbapi2.connect(str(database))
        try:
            apply_key(wrong_key, bytes.fromhex("0e" * 32))
            try:
                wrong_key.execute("SELECT count(*) FROM sqlite_master").fetchone()
            except dbapi2.DatabaseError:
                pass
            else:
                raise AssertionError("database opened with the wrong key")
        finally:
            wrong_key.close()

        child = os.fork()
        if child == 0:
            crashed = open_encrypted(dbapi2, database)
            crashed.execute("INSERT INTO memory VALUES (?)", (RECOVERY_CANARY.decode("ascii"),))
            crashed.commit()
            os.kill(os.getpid(), signal.SIGKILL)
        _, status = os.waitpid(child, 0)
        if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
            raise AssertionError("crash-recovery child did not terminate abruptly")
        recovered = open_encrypted(dbapi2, database)
        if recovered.execute(
            "SELECT count(*) FROM memory WHERE body=?", (RECOVERY_CANARY.decode("ascii"),)
        ).fetchone()[0] != 1:
            raise AssertionError("committed WAL record did not recover")
        if recovered.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise AssertionError("SQLite integrity check failed")
        cipher_findings = recovered.execute("PRAGMA cipher_integrity_check").fetchall()
        if cipher_findings:
            raise AssertionError("SQLCipher integrity check failed: %r" % (cipher_findings,))
        recovered.close()
        assert_no_canary(root)

    print(
        json.dumps(
            {
                "cipherVersion": cipher_version,
                "cacheTag": sys.implementation.cache_tag,
                "crashRecovery": "passed",
                "fts5": "passed",
                "integrity": "passed",
                "journalMode": journal_mode,
                "modulePath": str(module_path),
                "plaintextCanary": "absent",
                "platformMachine": platform.machine(),
                "pythonVersion": platform.python_version(),
                "sqliteVersion": dbapi2.sqlite_version,
                "status": "passed",
                "tempStore": "memory",
                "wrongAndMissingKeys": "rejected",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
