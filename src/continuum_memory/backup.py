"""LOCAL REVIEW CANDIDATE: encrypted staging/validation, not a backup command.

No CLI, MCP, publication or restore activation is wired to these primitives.
Owner authorization and native acceptance remain gates for the base backup work.
Independent revocation/freshness guarantees are separate issue-6 work, not a
prerequisite for implementing the base issue-4 backup/restore contract.
Missing native SQLCipher is an error, never a mock/plaintext fallback.
"""

import hmac
from pathlib import Path

from . import storage
from .admission import AdmissionPolicy, MAX_POLICY_BYTES, POLICY_FILE
from .audit_validation import verify_audit_snapshot
from .errors import MemoryError
from .migrations import SCHEMA_SQL, SCHEMA_VERSION
from .security import (bounded_id, canonical_json, ensure_private_directory, ensure_private_regular,
                       path_exists, read_private, write_private)
from .transport import decode_frame


FORMAT_VERSION = 2
APPLICATION_ID = 1129143636
BACKUP_STORAGE_MODES = {
    1: "continuum-backup-v1-sqlcipher-4.19.0",
    2: "continuum-backup-v2-sqlcipher-4.19.0",
}
BACKUP_STORAGE_MODE = BACKUP_STORAGE_MODES[FORMAT_VERSION]
MAX_MANIFEST_BYTES = 8192
MAX_BACKUP_BYTES = 256 * 1024 * 1024
MAX_SCHEMA_OBJECTS = 512
MAX_SCHEMA_BYTES = 64 * 1024
MAX_METADATA_BYTES = 128
MAX_AUDIT_EVENTS = 100_000
MAX_AUDIT_CELL_BYTES = 4096
ALIAS = "continuum_backup"
RESERVED_TABLES = {"continuum_backup_manifest", "continuum_backup_material"}
MANIFEST_SCHEMA = "CREATE TABLE continuum_backup_manifest (singleton INTEGER PRIMARY KEY CHECK(singleton=1), payload TEXT NOT NULL) STRICT"
MATERIAL_SCHEMA = "CREATE TABLE continuum_backup_material (singleton INTEGER PRIMARY KEY CHECK(singleton=1), audit_key BLOB NOT NULL, admission_policy BLOB) STRICT"


def _invalid():
    return MemoryError("backup_invalid", "The encrypted backup candidate failed validation.")


def validate_manifest(value):
    """Shape/integrity metadata only; never establish revocation freshness here."""
    try:
        expected = {"format_version", "vault_id", "recorded_seq", "user_version", "application_id",
                    "cipher_version", "source_storage_mode", "audit_head", "revocation_checkpoint"}
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError
        if len(canonical_json(value).encode("utf-8")) > MAX_MANIFEST_BYTES:
            raise ValueError
        version = value["format_version"]
        if type(version) is not int or version not in BACKUP_STORAGE_MODES:
            raise ValueError
        for name, required in (("user_version", SCHEMA_VERSION), ("application_id", APPLICATION_ID)):
            if type(value[name]) is not int or value[name] != required:
                raise ValueError
        if value["cipher_version"] != storage.SQLCIPHER_VERSION or value["source_storage_mode"] != storage.STORAGE_MODE:
            raise ValueError
        bounded_id(value["vault_id"], "vault_id")
        if type(value["recorded_seq"]) is not int or not 0 <= value["recorded_seq"] < 2**63:
            raise ValueError
        head = value["audit_head"]
        if not isinstance(head, dict) or set(head) != {"audit_seq", "mac"}:
            raise ValueError
        if type(head["audit_seq"]) is not int or not 0 <= head["audit_seq"] <= value["recorded_seq"]:
            raise ValueError
        _digest(head["mac"], genesis=head["audit_seq"] == 0)
        checkpoint = value["revocation_checkpoint"]
        if checkpoint is None:
            if version != 2:
                raise ValueError
        else:
            if not isinstance(checkpoint, dict) or set(checkpoint) != {"authority_id", "generation", "digest"}:
                raise ValueError
            bounded_id(checkpoint["authority_id"], "authority_id")
            if type(checkpoint["generation"]) is not int or not 0 <= checkpoint["generation"] < 2**63:
                raise ValueError
            _digest(checkpoint["digest"])
    except (ValueError, TypeError, UnicodeError, RecursionError, MemoryError):
        raise _invalid() from None
    return value


def _digest(value, genesis=False):
    if genesis:
        if value != "GENESIS":
            raise ValueError
    elif not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError


def read_backup_key_file(key_file, vault_dir, staging_dir):
    """Owner must separately approve this exact outside-vault/artifact key path."""
    try:
        key_file, vault_dir, staging_dir = map(Path, (key_file, vault_dir, staging_dir))
        for directory in (vault_dir, staging_dir, key_file.parent):
            ensure_private_directory(directory)
        ensure_private_regular(key_file, "Backup key")
        canonical_key = key_file.resolve(strict=True)
        if any(canonical_key == root.resolve(strict=True) or root.resolve(strict=True) in canonical_key.parents
               for root in (vault_dir, staging_dir)):
            raise ValueError
        key = read_private(key_file, storage.STORAGE_KEY_BYTES)
        if len(key) != storage.STORAGE_KEY_BYTES:
            raise ValueError
        if hmac.compare_digest(key, storage._read_storage_key(storage.paths(vault_dir)["storage_key"])):
            raise ValueError
        return key
    except (OSError, ValueError, MemoryError):
        raise MemoryError("backup_key_unavailable", "The separate owner-approved backup key is unavailable.") from None


def _schema(connection, alias="main"):
    if alias not in {"main", ALIAS}:
        raise _invalid()
    # Catalog text is archive-owned. Bound its aggregate before materializing it
    # in Python; this does not bound the native engine's own schema parsing time.
    count, size = connection.execute(
        "SELECT count(*),coalesce(sum(length(CAST(type AS BLOB)) + "
        "length(CAST(name AS BLOB)) + length(CAST(tbl_name AS BLOB)) + "
        "coalesce(length(CAST(sql AS BLOB)),0)),0) FROM " + alias + ".sqlite_schema"
    ).fetchone()
    if count > MAX_SCHEMA_OBJECTS or size > MAX_SCHEMA_BYTES:
        raise _invalid()
    rows = connection.execute("SELECT type,name,tbl_name,sql FROM " + alias + ".sqlite_schema ORDER BY type,name").fetchall()
    return [tuple(row) for row in rows]


def _bounded_metadata(connection):
    sizes = connection.execute(
        "SELECT key,length(CAST(value AS BLOB)) FROM metadata "
        "WHERE key IN ('storage_mode','vault_id') LIMIT 3"
    ).fetchall()
    if len(sizes) != 2 or any(not 0 < row[1] <= MAX_METADATA_BYTES for row in sizes):
        raise _invalid()
    return dict(connection.execute(
        "SELECT key,value FROM metadata WHERE key IN ('storage_mode','vault_id') LIMIT 3"
    ).fetchall())


def _require_bounded_audit(connection):
    # Only names from the compiled schema are interpolated. The helper verifies
    # HMACs after this preflight, without unbounded text-cell materialization.
    fields = ("actor_kind", "operation", "scoped_id", "target_id", "policy_decision",
              "result", "key_id", "occurred_at", "previous_mac", "mac")
    count = connection.execute(
        "SELECT count(*) FROM (SELECT 1 FROM audit_events LIMIT ?)",
        (MAX_AUDIT_EVENTS + 1,),
    ).fetchone()[0]
    if count > MAX_AUDIT_EVENTS:
        raise _invalid()
    predicate = " OR ".join("length(CAST(" + field + " AS BLOB)) > ?" for field in fields)
    if connection.execute("SELECT 1 FROM audit_events WHERE " + predicate + " LIMIT 1",
                          (MAX_AUDIT_CELL_BYTES,) * len(fields)).fetchone() is not None:
        raise _invalid()


def _candidate_fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_nlink)


def _expected_schema():
    """Build only compile-time trusted DDL, never replay archive-owned SQL."""
    storage._require_sqlcipher_runtime()
    connection = storage.sqlite3.connect(":memory:", isolation_level=None)
    try:
        connection.executescript(SCHEMA_SQL)
        connection.execute(MANIFEST_SCHEMA)
        connection.execute(MATERIAL_SCHEMA)
        return _schema(connection)
    finally:
        connection.close()


def _require_fresh_schema(connection, *, backup):
    """Candidate limit: exact fresh-v5 DDL, not every valid migrated v5 layout."""
    expected = _expected_schema()
    if not backup:
        expected = [row for row in expected if row[2] not in RESERVED_TABLES]
    if _schema(connection) != expected:
        raise _invalid()


def _require_single_file(path):
    # Even read-only SQLite can consume a WAL. The format promises one closed
    # artifact, so companions (including broken links) are never opened/repaired.
    if any(path_exists(Path(str(path) + suffix)) for suffix in ("-wal", "-shm", "-journal")):
        raise _invalid()


def _require_headers(connection):
    """Read only: the trusted bootstrap DDL sets this application identifier."""
    for pragma, expected in (("user_version", SCHEMA_VERSION), ("application_id", APPLICATION_ID),
                             ("auto_vacuum", 0)):
        if connection.execute("PRAGMA " + pragma).fetchone()[0] != expected:
            raise _invalid()


def _require_source_size(page_count, page_size):
    # Keyed SQLCipher returns page_size as decimal TEXT, unlike SQLite's
    # integer PRAGMA. Normalize only its bounded canonical representation.
    if type(page_size) is str:
        if (not 1 <= len(page_size) <= 5 or page_size[0] == "0"
                or any(character not in "0123456789" for character in page_size)):
            raise _invalid()
        page_size = int(page_size)
    if (type(page_size) is not int or not 512 <= page_size <= 65536
            or page_size & (page_size - 1)):
        raise _invalid()
    if (type(page_count) is not int or page_count <= 0
            or page_count > (MAX_BACKUP_BYTES - 65536) // page_size):
        raise _invalid()


def validate_candidate(path, key):
    """Check a presented candidate, not its freshness, without activating/repairing.

    File rechecks detect observed changes; they do not exclude unrestricted
    same-UID substitution/ABA races or establish independent restore authority.
    """
    connection = None
    try:
        path = Path(path)
        ensure_private_directory(path.parent)
        info = ensure_private_regular(path, "Backup candidate")
        storage.require_no_pending_rotation(path.parent)
        _require_single_file(path)
        if not 0 < info.st_size <= MAX_BACKUP_BYTES or not isinstance(key, bytes) or len(key) != 32:
            raise ValueError
        storage._require_sqlcipher_runtime()
        # mode=ro alone may create WAL/SHM files. This format admits only a
        # closed, companion-free artifact; immutable prevents VFS side effects.
        # The caller must keep it quiescent. Identity observations below do not
        # establish protection from unrestricted concurrent same-UID changes.
        connection = storage.sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)
        connection.row_factory = storage.sqlite3.Row
        connection.execute('PRAGMA key = "x\'%s\'"' % key.hex())
        if (connection.execute("PRAGMA cipher_version").fetchone()[0] != storage.SQLCIPHER_VERSION
                or str(connection.execute("PRAGMA cipher_status").fetchone()[0]) != "1"):
            raise ValueError
        connection.enable_load_extension(False)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA mmap_size=0")
        if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
            raise ValueError
        connection.execute("BEGIN")
        # Before touching archive-owned application tables, compare their entire
        # schema against this reviewed format. No dynamic schema SQL is executed.
        _require_fresh_schema(connection, backup=True)
        _require_headers(connection)
        if connection.execute("PRAGMA cipher_integrity_check").fetchone() is not None:
            raise ValueError
        integrity = connection.execute("PRAGMA integrity_check(1)")
        row = integrity.fetchone()
        if row is None or tuple(row) != ("ok",) or integrity.fetchone() is not None:
            raise ValueError
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ValueError
        sizes = connection.execute("SELECT length(CAST(payload AS BLOB)) FROM continuum_backup_manifest LIMIT 2").fetchall()
        if len(sizes) != 1 or not 0 < sizes[0][0] <= MAX_MANIFEST_BYTES:
            raise ValueError
        rows = connection.execute("SELECT payload FROM continuum_backup_manifest").fetchall()
        manifest = validate_manifest(decode_frame(rows[0][0].encode("utf-8")))
        sizes = connection.execute("SELECT length(audit_key),length(admission_policy) FROM continuum_backup_material LIMIT 2").fetchall()
        if len(sizes) != 1 or sizes[0][0] != 32 or (sizes[0][1] is not None and sizes[0][1] > MAX_POLICY_BYTES):
            raise ValueError
        material = connection.execute("SELECT audit_key,admission_policy FROM continuum_backup_material LIMIT 2").fetchall()
        if len(material) != 1 or not isinstance(material[0][0], bytes) or len(material[0][0]) != 32:
            raise ValueError
        policy = material[0][1]
        if policy is not None and (not isinstance(policy, bytes) or len(policy) > MAX_POLICY_BYTES):
            raise ValueError
        # Validate exactly the embedded bytes with the normal admission parser;
        # never write a plaintext policy file while validating an archive.
        AdmissionPolicy.from_bytes(policy)
        metadata = _bounded_metadata(connection)
        sequence = connection.execute("SELECT value FROM sequence WHERE singleton=1").fetchone()
        if (metadata.get("storage_mode") != BACKUP_STORAGE_MODES[manifest["format_version"]]
                or metadata.get("vault_id") != manifest["vault_id"]
                or not sequence or sequence[0] != manifest["recorded_seq"]):
            raise ValueError
        _require_bounded_audit(connection)
        if verify_audit_snapshot(connection, material[0][0], lambda: manifest["audit_head"])["status"] != "valid":
            raise ValueError
        _require_single_file(path)
        if _candidate_fingerprint(ensure_private_regular(path, "Backup candidate")) != _candidate_fingerprint(info):
            raise ValueError
        return {"status": "validated_not_activated", "format_version": manifest["format_version"],
                "restore_ready": False, "freshness": "unverified",
                "revocation_reconciliation": "not_performed", "manifest": manifest}
    except Exception:
        raise _invalid() from None
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                raise _invalid() from None


def _export_control_snapshot(path, maximum, *, optional=False):
    """Bounded bytes and observed identity, not a same-UID race guarantee."""
    def fingerprint(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)

    try:
        if optional and not path_exists(path):
            return None, None
        before = ensure_private_regular(path, "Backup source control material")
        if before.st_size > maximum:
            raise _invalid()
        payload = read_private(path, maximum)
        after = ensure_private_regular(path, "Backup source control material")
        if fingerprint(before) != fingerprint(after) or len(payload) != after.st_size:
            raise _invalid()
        return payload, fingerprint(after)
    except Exception:
        raise _invalid() from None


def _export_control_unchanged(path, maximum, expected, *, optional=False):
    current = _export_control_snapshot(path, maximum, optional=optional)
    if current[1] != expected[1]:
        raise _invalid()
    if current[0] is None or expected[0] is None:
        if current[0] is not expected[0]:
            raise _invalid()
    elif not hmac.compare_digest(current[0], expected[0]):
        raise _invalid()


def _export_cleanup(store, connection):
    """Restore the caller's connection, or close it and refuse further use."""
    try:
        # Inspect actual state: BEGIN/COMMIT/ATTACH may have taken effect even
        # if their call was interrupted before returning to the caller.
        if connection.in_transaction:
            store.rollback()
        if connection.in_transaction:
            raise _invalid()
        if ALIAS in {row[1] for row in connection.execute("PRAGMA database_list")}:
            connection.execute("DETACH DATABASE continuum_backup")
        if connection.in_transaction or ALIAS in {
            row[1] for row in connection.execute("PRAGMA database_list")
        }:
            raise _invalid()
        return True
    except BaseException:
        try:
            connection.close()
        except BaseException:
            # A failed close must not leave a usable Store reference behind.
            store.connection = None
        return False


def export_candidate(store, staging_dir, key_file, revocation_checkpoint=None):
    """Stage an encrypted snapshot; the caller owns authorization and the lease.

    The caller must serialize access to Store and hold the cooperating DaemonLock
    for its entire lifetime/export; a SQL transaction alone does not exclude
    offline rotation. No CLI/MCP calls this primitive. New format-v2 exports
    record an absent checkpoint as null; a supplied checkpoint never proves
    freshness or revocation.
    Failures retain private residue: before commit it is partial; a failed or
    interrupted commit can leave a complete but unpublished candidate. Never
    delete or retry it automatically. No power-loss durability is asserted.
    """
    try:
        return _export_candidate(store, staging_dir, key_file, revocation_checkpoint)
    except MemoryError as error:
        if error.code in {"backup_invalid", "backup_busy", "backup_destination_exists",
                          "backup_key_unavailable", "rotation_pending", "rotation_recovery_refused"}:
            raise
        raise _invalid() from None
    except Exception:
        raise _invalid() from None


def _export_candidate(store, staging_dir, key_file, revocation_checkpoint):
    staging_dir = Path(staging_dir)
    ensure_private_directory(staging_dir)
    ensure_private_directory(store.data_dir)
    source_root, staging_root = Path(store.data_dir).resolve(), staging_dir.resolve()
    if (source_root == staging_root or source_root in staging_root.parents
            or staging_root in source_root.parents):
        raise _invalid()
    storage.require_no_pending_rotation(store.data_dir)
    storage.require_no_pending_rotation(staging_dir)
    connection = store.connection
    try:
        busy = connection.in_transaction
        aliases = {row[1] for row in connection.execute("PRAGMA database_list")}
    except Exception:
        raise _invalid() from None
    if busy:
        raise MemoryError("backup_busy", "The vault already has an active transaction.")
    if ALIAS in aliases:
        raise MemoryError("backup_busy", "The backup database alias is already in use.")
    source_key_path = storage.paths(store.data_dir)["storage_key"]
    source_key = _export_control_snapshot(source_key_path, storage.STORAGE_KEY_BYTES)
    if len(source_key[0]) != storage.STORAGE_KEY_BYTES:
        raise _invalid()
    key = read_backup_key_file(key_file, store.data_dir, staging_dir)
    key_file = Path(key_file)
    backup_key = _export_control_snapshot(key_file, storage.STORAGE_KEY_BYTES)
    if not hmac.compare_digest(key, backup_key[0]):
        raise _invalid()
    if hmac.compare_digest(key, source_key[0]):
        raise _invalid()
    target = staging_dir / "backup.cdb"
    if path_exists(target):
        raise MemoryError("backup_destination_exists", "The backup staging destination is occupied.")
    _require_single_file(target)
    write_private(target, b"")
    try:
        store.begin()
        _require_fresh_schema(connection, backup=False)
        _require_headers(connection)
        metadata = _bounded_metadata(connection)
        if metadata["storage_mode"] != storage.STORAGE_MODE or metadata["vault_id"] != store.vault_id:
            raise _invalid()
        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        _require_source_size(page_count, page_size)
        audit_key_path = store.files["audit_key"]
        audit_head_path = store.files["audit_head"]
        audit_key = _export_control_snapshot(audit_key_path, 32)
        audit_head = _export_control_snapshot(audit_head_path, 1024)
        if len(audit_key[0]) != 32 or not hmac.compare_digest(audit_key[0], store.audit_key):
            raise _invalid()
        head = decode_frame(audit_head[0])
        _require_bounded_audit(connection)
        if verify_audit_snapshot(connection, audit_key[0], lambda: head)["status"] != "valid":
            raise _invalid()
        policy_path = store.data_dir / POLICY_FILE
        policy = _export_control_snapshot(policy_path, MAX_POLICY_BYTES, optional=True)
        AdmissionPolicy.from_bytes(policy[0])
        manifest = validate_manifest({"format_version": FORMAT_VERSION, "vault_id": store.vault_id,
            "recorded_seq": connection.execute("SELECT value FROM sequence WHERE singleton=1").fetchone()[0],
            "user_version": SCHEMA_VERSION, "application_id": APPLICATION_ID,
            "cipher_version": storage.SQLCIPHER_VERSION, "source_storage_mode": storage.STORAGE_MODE,
            "audit_head": head, "revocation_checkpoint": revocation_checkpoint})
        connection.execute("ATTACH DATABASE ? AS continuum_backup KEY ?", (str(target), "x'%s'" % key.hex()))
        if str(connection.execute("PRAGMA continuum_backup.cipher_status").fetchone()[0]) != "1":
            raise _invalid()
        connection.execute("PRAGMA continuum_backup.auto_vacuum=0")
        if connection.execute("PRAGMA continuum_backup.auto_vacuum").fetchone()[0] != 0:
            raise _invalid()
        connection.execute("SELECT sqlcipher_export(?, ?)", (ALIAS, "main")).fetchall()
        connection.execute("PRAGMA continuum_backup.user_version=%d" % SCHEMA_VERSION)
        connection.execute("PRAGMA continuum_backup.application_id=%d" % APPLICATION_ID)
        for pragma, expected in (("user_version", SCHEMA_VERSION), ("application_id", APPLICATION_ID),
                                 ("auto_vacuum", 0)):
            if connection.execute("PRAGMA continuum_backup." + pragma).fetchone()[0] != expected:
                raise _invalid()
        for statement in (MANIFEST_SCHEMA, MATERIAL_SCHEMA):
            connection.execute(statement.replace("CREATE TABLE ", "CREATE TABLE continuum_backup.", 1))
        connection.execute("INSERT INTO continuum_backup.continuum_backup_manifest VALUES (1,?)", (canonical_json(manifest),))
        connection.execute("INSERT INTO continuum_backup.continuum_backup_material VALUES (1,?,?)", (audit_key[0], policy[0]))
        connection.execute("UPDATE continuum_backup.metadata SET value=? WHERE key='storage_mode'", (BACKUP_STORAGE_MODE,))
        storage.require_no_pending_rotation(store.data_dir)
        storage.require_no_pending_rotation(staging_dir)
        _export_control_unchanged(audit_key_path, 32, audit_key)
        _export_control_unchanged(audit_head_path, 1024, audit_head)
        _export_control_unchanged(policy_path, MAX_POLICY_BYTES, policy, optional=True)
        _export_control_unchanged(key_file, storage.STORAGE_KEY_BYTES, backup_key)
        _export_control_unchanged(source_key_path, storage.STORAGE_KEY_BYTES, source_key)
        connection.commit()
    except BaseException as error:
        if not _export_cleanup(store, connection):
            raise _invalid() from None
        if not isinstance(error, Exception):
            raise
        raise _invalid() from None
    if not _export_cleanup(store, connection):
        raise _invalid() from None
    try:
        result = validate_candidate(target, key)
        _export_control_unchanged(key_file, storage.STORAGE_KEY_BYTES, backup_key)
    except Exception:
        raise _invalid() from None
    result["status"] = "staged_not_published"
    return result
