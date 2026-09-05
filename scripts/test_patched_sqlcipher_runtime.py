#!/usr/bin/env python3
"""Runtime security and recovery tests for an installed patched SQLCipher wheel."""

import json
import os
import tempfile
from pathlib import Path

from sqlcipher3 import dbapi2


CANARY = b"CONTINUUM_PATCHED_SQLCIPHER_CANARY_5c7b41"
KEY = bytes.fromhex("f1" * 32)


def apply_key(connection, key: bytes = KEY) -> None:
    connection.execute("PRAGMA key = \"x'%s'\"" % key.hex())


def open_encrypted(path: Path):
    connection = dbapi2.connect(str(path))
    apply_key(connection)
    connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
    return connection


def assert_no_canary(directory: Path) -> None:
    for path in directory.iterdir():
        if path.is_file() and CANARY in path.read_bytes():
            raise AssertionError("plaintext canary found in %s" % path.name)


def main() -> int:
    if dbapi2.sqlite_version != "3.53.4":
        raise AssertionError("unexpected SQLite runtime: %s" % dbapi2.sqlite_version)
    with tempfile.TemporaryDirectory(prefix="continuum-patched-sqlcipher-") as temporary:
        root = Path(temporary)
        os.environ["SQLITE_TMPDIR"] = str(root)
        database = root / "vault.db"
        connection = open_encrypted(database)
        cipher_version = connection.execute("PRAGMA cipher_version").fetchone()[0]
        if cipher_version != "4.18.0 community":
            raise AssertionError("unexpected SQLCipher runtime: %s" % cipher_version)
        if connection.execute("PRAGMA cipher_status").fetchone()[0] != 1:
            raise AssertionError("SQLCipher encryption is not active")
        options = {row[0] for row in connection.execute("PRAGMA compile_options")}
        if "ENABLE_FTS5" not in options or "TEMP_STORE=2" not in options:
            raise AssertionError("required SQLite compile options are missing")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA secure_delete=ON")
        connection.enable_load_extension(False)
        connection.execute("CREATE TABLE memory(body TEXT NOT NULL)")
        connection.execute("CREATE VIRTUAL TABLE memory_fts USING fts5(body)")
        connection.execute("INSERT INTO memory VALUES (?)", (CANARY.decode("ascii"),))
        connection.execute("INSERT INTO memory_fts VALUES (?)", (CANARY.decode("ascii"),))
        connection.commit()
        if connection.execute("SELECT body FROM memory_fts WHERE memory_fts MATCH 'CANARY'").fetchone()[0].encode() != CANARY:
            raise AssertionError("FTS5 encrypted content did not round-trip")
        if database.read_bytes().startswith(b"SQLite format 3\x00"):
            raise AssertionError("database has a plaintext SQLite header")
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
            crashed = open_encrypted(database)
            crashed.execute("INSERT INTO memory VALUES ('recovery-record')")
            crashed.commit()
            os._exit(0)
        _, status = os.waitpid(child, 0)
        if status != 0:
            raise AssertionError("crash-recovery child failed")
        recovered = open_encrypted(database)
        if recovered.execute("SELECT count(*) FROM memory WHERE body='recovery-record'").fetchone()[0] != 1:
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
                "crashRecovery": "passed",
                "fts5": "passed",
                "integrity": "passed",
                "plaintextCanary": "absent",
                "sqliteVersion": dbapi2.sqlite_version,
                "status": "passed",
                "wrongAndMissingKeys": "rejected",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
