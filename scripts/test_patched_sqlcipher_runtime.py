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


def assert_no_plaintext(directory: Path) -> None:
    assert_no_canary(directory)
    for path in directory.iterdir():
        if path.is_file() and path.read_bytes().startswith(b"SQLite format 3\x00"):
            raise AssertionError("plaintext SQLite header found in %s" % path.name)


def test_uri_hexkey(dbapi2, root: Path) -> None:
    # The URI decodes hex into passphrase bytes, not PRAGMA's x'raw-key' syntax.
    passphrase = "synthetic-uri-key-for-tests-only"
    valid_database = root / "uri-valid.db"
    connection = dbapi2.connect(
        valid_database.as_uri() + "?mode=rwc&hexkey=" + passphrase.encode("ascii").hex(),
        uri=True,
    )
    try:
        require_active_cipher(connection.execute("PRAGMA cipher_status").fetchone()[0])
        connection.execute("CREATE TABLE uri_memory(body TEXT NOT NULL)")
        connection.execute("INSERT INTO uri_memory VALUES (?)", (CANARY.decode("ascii"),))
        connection.commit()
    finally:
        connection.close()
    reopened = dbapi2.connect(str(valid_database))
    try:
        # This fixed synthetic literal is the same passphrase used in the URI.
        reopened.execute("PRAGMA key = '%s'" % passphrase)
        require_active_cipher(reopened.execute("PRAGMA cipher_status").fetchone()[0])
        if reopened.execute("SELECT body FROM uri_memory").fetchall() != [(CANARY.decode("ascii"),)]:
            raise AssertionError("valid URI key did not round-trip through PRAGMA key")
    finally:
        reopened.close()
    assert_no_plaintext(root)

    # Both nonempty inputs decode to zero key bytes. The advisory does not promise
    # strict rejection of every value with a valid prefix followed by invalid hex.
    for index, invalid_key in enumerate(("zz", "0")):
        database = root / ("uri-invalid-%d.db" % index)
        connection = None
        rejected = False
        try:
            connection = dbapi2.connect(database.as_uri() + "?mode=rwc&hexkey=" + invalid_key, uri=True)
            connection.execute("CREATE TABLE uri_memory(body TEXT NOT NULL)")
            connection.execute("INSERT INTO uri_memory VALUES (?)", (CANARY.decode("ascii"),))
            connection.commit()
        except dbapi2.DatabaseError:
            rejected = True
        finally:
            if connection is not None:
                connection.close()
        # Opening may leave an empty file; it must never leave plaintext content.
        assert_no_plaintext(root)
        if not rejected:
            raise AssertionError("nonempty URI hexkey without key material was accepted")


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def test_quoted_schema_export(dbapi2, root: Path) -> None:
    source_alias = "source\" quoted; ' schema"
    target_alias = "target\" quoted; ' schema"
    source = quote_identifier(source_alias)
    target = quote_identifier(target_alias)
    source_database = root / "export-source.db"
    target_database = root / "export-target.db"
    connection = open_encrypted(dbapi2, root / "export-control.db")
    expected_rows = [(1, CANARY.decode("ascii"))]
    try:
        connection.execute("CREATE TABLE sentinel(body TEXT NOT NULL)")
        connection.execute("INSERT INTO sentinel VALUES ('unchanged')")
        connection.commit()
        for database, schema in ((source_database, source), (target_database, target)):
            connection.execute(
                "ATTACH DATABASE ? AS %s KEY ?" % schema,
                (str(database), "x'%s'" % KEY.hex()),
            )
            require_active_cipher(connection.execute("PRAGMA %s.cipher_status" % schema).fetchone()[0])
        connection.execute(
            "CREATE TABLE %s.export_memory(id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL)" % source
        )
        connection.execute("CREATE INDEX %s.export_body ON export_memory(body)" % source)
        connection.execute("INSERT INTO %s.export_memory(body) VALUES (?)" % source, (CANARY.decode("ascii"),))
        connection.commit()
        schema_query = "SELECT type,name,tbl_name,sql FROM %s.sqlite_schema ORDER BY type,name"
        expected_schema = connection.execute(schema_query % source).fetchall()
        # Aliases are bound as values here; the native function must quote them
        # when constructing its own SQL. Both source and target need protection.
        connection.execute("SELECT sqlcipher_export(?, ?)", (target_alias, source_alias)).fetchall()
        connection.commit()
        for schema in (source, target):
            if connection.execute("SELECT id,body FROM %s.export_memory ORDER BY id" % schema).fetchall() != expected_rows:
                raise AssertionError("export source or target content changed unexpectedly")
            if connection.execute(schema_query % schema).fetchall() != expected_schema:
                raise AssertionError("export source or target schema changed unexpectedly")
            if connection.execute("SELECT seq FROM %s.sqlite_sequence WHERE name='export_memory'" % schema).fetchall() != [(1,)]:
                raise AssertionError("export source or target sequence changed unexpectedly")
        if connection.execute("SELECT body FROM main.sentinel").fetchall() != [("unchanged",)]:
            raise AssertionError("export changed the unrelated sentinel")
        if connection.execute("SELECT name FROM main.sqlite_schema ORDER BY name").fetchall() != [("sentinel",)]:
            raise AssertionError("export altered the unrelated main schema")
        assert_no_plaintext(root)
    finally:
        connection.close()
    for database in (source_database, target_database):
        reopened = open_encrypted(dbapi2, database)
        try:
            require_active_cipher(reopened.execute("PRAGMA cipher_status").fetchone()[0])
            if reopened.execute("SELECT id,body FROM export_memory ORDER BY id").fetchall() != expected_rows:
                raise AssertionError("exported encrypted content did not survive keyed reopen")
            if reopened.execute(schema_query % "main").fetchall() != expected_schema:
                raise AssertionError("exported schema did not survive keyed reopen")
            if reopened.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise AssertionError("exported SQLite integrity check failed")
            if reopened.execute("PRAGMA cipher_integrity_check").fetchall():
                raise AssertionError("exported SQLCipher integrity check failed")
        finally:
            reopened.close()
    assert_no_plaintext(root)


def main() -> int:
    from sqlcipher3 import dbapi2

    module_path = Path(dbapi2.__file__).resolve()
    runtime_prefix = Path(sys.prefix).resolve()
    if runtime_prefix not in module_path.parents:
        raise AssertionError("sqlcipher3 imported outside the isolated runtime environment")
    distribution = metadata.distribution("continuum-sqlcipher3")
    if distribution.version != "0.6.2.post2":
        raise AssertionError("unexpected installed distribution version")
    if dbapi2.sqlite_version != "3.53.4":
        raise AssertionError("unexpected SQLite runtime: %s" % dbapi2.sqlite_version)
    with tempfile.TemporaryDirectory(prefix="continuum-patched-sqlcipher-") as temporary:
        root = Path(temporary)
        os.environ["SQLITE_TMPDIR"] = str(root)
        database = root / "vault.db"
        connection = open_encrypted(dbapi2, database)
        cipher_version = connection.execute("PRAGMA cipher_version").fetchone()[0]
        if cipher_version != "4.19.0 community":
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
        try:
            connection.load_extension(str(root / "continuum-extension-must-not-load.so"))
        except dbapi2.OperationalError as error:
            if "not authorized" not in str(error).lower():
                raise AssertionError(
                    "extension loading reached the filesystem before explicit enablement"
                ) from error
        else:
            raise AssertionError("extension loading was enabled by default")
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
        test_uri_hexkey(dbapi2, root)
        test_quoted_schema_export(dbapi2, root)

    print(
        json.dumps(
            {
                "cipherVersion": cipher_version,
                "cacheTag": sys.implementation.cache_tag,
                "crashRecovery": "passed",
                "extensionLoadingDefault": "denied",
                "exportQuotedSchemas": "passed",
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
                "uriHexkeyInvalidMaterial": "rejected",
                "uriHexkeyValidRoundTrip": "passed",
                "wrongAndMissingKeys": "rejected",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
