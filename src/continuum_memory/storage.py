"""SQLCipher bootstrap, connection hardening, sequencing, and audit integrity."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
from importlib import metadata

try:
    from sqlcipher3 import dbapi2 as sqlite3
except ImportError:
    sqlite3 = None  # Runtime admission fails closed; help/metadata remain available.
from pathlib import Path
from typing import Any, Dict, List, Optional

from .admission import AdmissionPolicy
from .audit_validation import verify_audit_snapshot
from .errors import CommittedAuditError, MemoryError
from .migrations import SCHEMA_SQL, SCHEMA_VERSION, migrate
from .security import (
    MAX_BODY_BYTES,
    MAX_SUBJECT_BYTES,
    bounded_id,
    bounded_provider,
    bounded_text,
    canonical_json,
    ensure_private_directory,
    ensure_private_regular,
    ensure_safe_ancestors,
    now_iso,
    path_exists,
    random_id,
    read_private,
    replace_private,
    token_hash,
    write_private,
)
from .transport import decode_frame

POLICY_VERSION = "prototype-1"
AUDIT_KEY_ID = "prototype-local-hmac-1"
SQLCIPHER_VERSION = "4.19.0 community"
STORAGE_KEY_BYTES = 32
STORAGE_MODE = "sqlcipher-4.19.0"
REQUIRED_CONNECTION_SETTINGS = {
    "busy_timeout": 5000,
    "foreign_keys": 1,
    "mmap_size": 0,
    "query_only": 0,
    "secure_delete": 1,
    "synchronous": 2,
    "temp_store": 2,
    "trusted_schema": 0,
}



def paths(data_dir: Path) -> Dict[str, Path]:
    return {
        "db": data_dir / "continuum.db",
        "socket": data_dir / "memoryd.sock",
        "storage_key": data_dir / "storage.key",
        "rotation_state": data_dir / "storage.rotation.json",
        "next_storage_key": data_dir / "storage.key.next",
        "audit_key": data_dir / "audit.key",
        "audit_head": data_dir / "audit.head",
        "control": data_dir / "control.cap",
        "caps": data_dir / "capabilities",
    }


def require_no_pending_rotation(data_dir: Path) -> None:
    file_map = paths(data_dir)
    if any(path_exists(file_map[name]) for name in ("rotation_state", "next_storage_key")):
        raise MemoryError(
            "rotation_pending",
            "Storage key rotation requires explicit offline recovery before opening the vault.",
        )


def _read_storage_key(key_path: Path) -> bytes:
    try:
        key = read_private(key_path, STORAGE_KEY_BYTES)
    except (MemoryError, OSError):
        raise MemoryError(
            "storage_key_unavailable",
            "The vault storage key is unavailable.",
        ) from None
    if len(key) != STORAGE_KEY_BYTES:
        raise MemoryError(
            "storage_key_unavailable",
            "The vault storage key is unavailable.",
        )
    return key


def _sync_private_directory(directory: Path) -> None:
    expected = ensure_private_directory(directory)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(str(directory), flags)
        try:
            opened = os.fstat(fd)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or opened.st_dev != expected.st_dev
                or opened.st_ino != expected.st_ino
            ):
                raise MemoryError("unsafe_directory", "The private data directory changed.")
            os.fsync(fd)
        finally:
            os.close(fd)
    except MemoryError:
        raise
    except OSError:
        raise MemoryError(
            "storage_key_unavailable",
            "The vault storage key could not be made durable.",
        ) from None


def _require_sqlcipher_runtime() -> None:
    if sqlite3 is None:
        raise MemoryError(
            "sqlcipher_unavailable",
            "The required encrypted storage runtime is unavailable.",
        )
    try:
        if metadata.version("continuum-sqlcipher3") != "0.6.2.post2":
            raise metadata.PackageNotFoundError("continuum-sqlcipher3")
    except metadata.PackageNotFoundError:
        raise MemoryError("sqlcipher_unavailable", "The required encrypted storage runtime is unavailable.") from None
    if sqlite3.sqlite_version != "3.53.4":
        raise MemoryError("sqlcipher_unavailable", "The required encrypted storage runtime is unavailable.")
    try:
        connection = sqlite3.connect(":memory:", isolation_level=None)
    except sqlite3.Error:
        raise MemoryError(
            "sqlcipher_unavailable",
            "The required encrypted storage runtime is unavailable.",
        ) from None
    try:
        connection.execute('PRAGMA key = "x\'%s\'"' % (b"\x00" * STORAGE_KEY_BYTES).hex())
        cipher_row = connection.execute("PRAGMA cipher_version").fetchone()
        status_row = connection.execute("PRAGMA cipher_status").fetchone()
        if (
            not cipher_row
            or cipher_row[0] != SQLCIPHER_VERSION
            or not status_row
            or str(status_row[0]) != "1"
        ):
            raise MemoryError(
                "sqlcipher_unavailable",
                "The required encrypted storage runtime is unavailable.",
            )
    except MemoryError:
        raise
    except sqlite3.Error:
        raise MemoryError(
            "sqlcipher_unavailable",
            "The required encrypted storage runtime is unavailable.",
        ) from None
    finally:
        connection.close()


def _read_connection_settings(
    connection: sqlite3.Connection,
    include_journal: bool = False,
) -> Dict[str, Any]:
    pragmas = {
        "busy_timeout": "busy_timeout",
        "foreign_keys": "foreign_keys",
        "mmap_size": "mmap_size",
        "query_only": "query_only",
        "secure_delete": "secure_delete",
        "synchronous": "synchronous",
        "temp_store": "temp_store",
        "trusted_schema": "trusted_schema",
    }
    settings: Dict[str, Any] = {}
    for name, pragma in pragmas.items():
        row = connection.execute("PRAGMA %s" % pragma).fetchone()
        if not row:
            raise MemoryError(
                "storage_hardening_failed",
                "The encrypted storage safety settings could not be applied.",
            )
        settings[name] = int(row[0])
    if include_journal:
        journal = connection.execute("PRAGMA journal_mode").fetchone()
        if not journal:
            raise MemoryError(
                "storage_hardening_failed",
                "The encrypted storage safety settings could not be applied.",
            )
        settings["journal_mode"] = str(journal[0]).lower()
    return settings


def _validate_database_artifacts(db_path: Path) -> None:
    ensure_private_regular(db_path, "The vault database")
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(db_path) + suffix)
        if path_exists(sidecar):
            ensure_private_regular(sidecar, "The SQLite %s sidecar" % suffix[1:])


def _apply_connection_hardening(connection: sqlite3.Connection, db_path: Path) -> None:
    try:
        connection.enable_load_extension(False)
    except (AttributeError, sqlite3.NotSupportedError):
        pass
    if sqlite3.sqlite_version_info < (3, 37, 0):
        raise MemoryError("unsupported_sqlite", "SQLite 3.37 or newer is required for strict schemas.")
    try:
        connection.execute("PRAGMA query_only=OFF")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA mmap_size=0")
        if _read_connection_settings(connection) != REQUIRED_CONNECTION_SETTINGS:
            raise MemoryError(
                "storage_hardening_failed",
                "The encrypted storage safety settings could not be applied.",
            )
        connection.execute("PRAGMA journal_mode=WAL")
        expected = dict(REQUIRED_CONNECTION_SETTINGS, journal_mode="wal")
        if _read_connection_settings(connection, include_journal=True) != expected:
            raise MemoryError(
                "storage_hardening_failed",
                "The encrypted storage safety settings could not be applied.",
            )
    except MemoryError:
        raise
    except sqlite3.Error:
        raise MemoryError(
            "storage_hardening_failed",
            "The encrypted storage safety settings could not be applied.",
        ) from None
    try:
        connection.execute("CREATE VIRTUAL TABLE temp.continuum_fts_probe USING fts5(value)")
        connection.execute("DROP TABLE temp.continuum_fts_probe")
    except sqlite3.Error:
        raise MemoryError("fts5_unavailable", "The SQLite runtime does not provide FTS5.") from None
    _validate_database_artifacts(db_path)


def _connect(
    db_path: Path,
    storage_key: bytes,
    apply_hardening: bool = False,
) -> sqlite3.Connection:
    ensure_private_directory(db_path.parent)
    _validate_database_artifacts(db_path)
    _require_sqlcipher_runtime()
    if len(storage_key) != STORAGE_KEY_BYTES:
        raise MemoryError("storage_key_unavailable", "The vault storage key is unavailable.")
    try:
        connection = sqlite3.connect(db_path.resolve().as_uri() + "?mode=rw", uri=True, timeout=5.0, isolation_level=None)
    except sqlite3.Error:
        raise MemoryError("storage_unavailable", "The encrypted vault could not be opened.") from None
    connection.row_factory = sqlite3.Row
    try:
        # SQLCipher requires the key to be the first operation on a new connection.
        # Hex encoding constrains the interpolated value to a non-injectable alphabet.
        connection.execute('PRAGMA key = "x\'%s\'"' % storage_key.hex())
        cipher_row = connection.execute("PRAGMA cipher_version").fetchone()
        status_row = connection.execute("PRAGMA cipher_status").fetchone()
        if (
            not cipher_row
            or cipher_row[0] != SQLCIPHER_VERSION
            or not status_row
            or str(status_row[0]) != "1"
        ):
            raise MemoryError(
                "sqlcipher_unavailable",
                "The required encrypted storage runtime is unavailable.",
            )
        if not apply_hardening:
            connection.execute("PRAGMA query_only=ON")
            query_only = connection.execute("PRAGMA query_only").fetchone()
            if not query_only or int(query_only[0]) != 1:
                raise MemoryError(
                    "storage_validation_failed",
                    "The encrypted vault's query-only preflight could not be enabled.",
                )
        # Force page authentication before applying any write-affecting pragmas.
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except MemoryError:
        connection.close()
        raise
    except sqlite3.Error:
        connection.close()
        raise MemoryError(
            "storage_key_invalid",
            "The encrypted vault could not be opened.",
        ) from None
    if apply_hardening:
        try:
            _apply_connection_hardening(connection, db_path)
        except Exception:
            connection.close()
            raise
    return connection


def _capability_document(project_id: Optional[str], provider: str, permissions: List[str], token: str) -> bytes:
    value = {
        "schema_version": 1,
        "project_id": project_id,
        "provider": provider,
        "permissions": sorted(permissions),
        "token": token,
    }
    return (canonical_json(value) + "\n").encode("utf-8")


class Store:
    def __init__(self, data_dir: Path):
        self._initialize(data_dir, allow_rotation=False)

    @classmethod
    def _open_during_rotation(cls, data_dir: Path):
        """Internal maintenance opener; the caller must hold the daemon lease."""
        store = cls.__new__(cls)
        store._initialize(data_dir, allow_rotation=True)
        return store

    def _initialize(self, data_dir: Path, *, allow_rotation: bool) -> None:
        self.data_dir = data_dir
        self.files = paths(data_dir)
        directory_info = ensure_private_directory(data_dir)
        self.owner_uid = int(directory_info.st_uid)
        if not allow_rotation:
            require_no_pending_rotation(data_dir)
            # Normal operation uses WAL. A rollback journal belongs to offline
            # maintenance or an unknown state: opening it can replay pages even
            # with query_only enabled, before metadata admission is possible.
            if path_exists(Path(str(self.files["db"]) + "-journal")):
                raise MemoryError(
                    "storage_recovery_required",
                    "An unexpected rollback journal requires offline investigation.",
                )
        if not path_exists(self.files["db"]):
            raise MemoryError("not_initialized", "The selected Continuum home is not initialized.")
        ensure_private_regular(self.files["db"], "The vault database")
        storage_key = _read_storage_key(self.files["storage_key"])
        audit_key = read_private(self.files["audit_key"], 128)
        connection = _connect(self.files["db"], storage_key)
        try:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (2, 3, 4, SCHEMA_VERSION):
                raise MemoryError("schema_mismatch", "The vault schema version is unsupported.")
            mode = connection.execute("SELECT value FROM metadata WHERE key='storage_mode'").fetchone()
            if not mode or mode[0] != STORAGE_MODE:
                raise MemoryError("storage_mode_mismatch", "The vault storage mode is unsupported.")
            vault = connection.execute("SELECT value FROM metadata WHERE key='vault_id'").fetchone()
            if not vault:
                raise MemoryError("integrity_error", "The vault identity is unavailable.")
            vault_id = bounded_id(vault[0], "vault_id")
            # Admit the encrypted format and identity before enabling writes or schema upgrades.
            _apply_connection_hardening(connection, self.files["db"])
            if migrate(connection, version) != SCHEMA_VERSION:
                raise MemoryError("schema_mismatch", "The vault schema version is unsupported.")
        except MemoryError:
            connection.close()
            raise
        except sqlite3.Error:
            connection.close()
            raise MemoryError("integrity_error", "The encrypted vault metadata is invalid.") from None
        except BaseException:
            connection.close()
            raise
        self.connection = connection
        self.vault_id = vault_id
        self.storage_mode = STORAGE_MODE
        self.audit_key = audit_key

    @classmethod
    def bootstrap(cls, data_dir: Path, projects: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not projects or len(projects) > 16:
            raise MemoryError("invalid_request", "Bootstrap requires one to sixteen projects.")
        admission_policy = AdmissionPolicy.load(data_dir)
        normalized_projects = []
        for spec in projects:
            if set(spec) != {"name", "path_hint", "providers"}:
                raise MemoryError("invalid_request", "Project bootstrap fields are invalid.")
            name = bounded_text(spec["name"], "project_name", MAX_SUBJECT_BYTES)
            path_hint = bounded_text(spec["path_hint"], "path_hint", MAX_BODY_BYTES)
            if not isinstance(spec["providers"], list):
                raise MemoryError("invalid_request", "Project providers must be a list.")
            providers = sorted({bounded_provider(item) for item in spec["providers"]})
            if not providers or len(providers) > 8:
                raise MemoryError("invalid_request", "Each project requires one to eight providers.")
            admission_policy.check([name, path_hint] + providers)
            normalized_projects.append({"name": name, "path_hint": path_hint, "providers": providers})
        projects = normalized_projects
        _require_sqlcipher_runtime()
        if path_exists(data_dir):
            ensure_private_directory(data_dir)
            require_no_pending_rotation(data_dir)
        else:
            ensure_safe_ancestors(data_dir.parent)
            data_dir.mkdir(mode=0o700, parents=True)
            os.chmod(str(data_dir), 0o700)
            ensure_private_directory(data_dir)
        file_map = paths(data_dir)
        occupied = ("db", "socket", "storage_key", "audit_key", "audit_head", "control", "caps")
        sidecars = [Path(str(file_map["db"]) + suffix) for suffix in ("-wal", "-shm", "-journal")]
        if (any(path_exists(file_map[name]) for name in occupied)
                or any(path_exists(path) for path in sidecars)):
            raise MemoryError("already_initialized", "The selected Continuum home is already initialized.")
        file_map["caps"].mkdir(mode=0o700)
        os.chmod(str(file_map["caps"]), 0o700)
        ensure_private_directory(file_map["caps"])
        storage_key = secrets.token_bytes(STORAGE_KEY_BYTES)
        audit_key = secrets.token_bytes(32)
        write_private(file_map["storage_key"], storage_key)
        _sync_private_directory(data_dir)
        write_private(file_map["audit_key"], audit_key)
        control_token = secrets.token_urlsafe(32)
        write_private(
            file_map["control"],
            _capability_document(None, "user_control", ["control", "read"], control_token),
        )
        write_private(file_map["db"], b"")
        connection = _connect(file_map["db"], storage_key, apply_hardening=True)
        try:
            connection.executescript(SCHEMA_SQL)
            connection.execute("PRAGMA user_version=%d" % SCHEMA_VERSION)
            connection.execute("BEGIN IMMEDIATE")
            vault_id = random_id("vlt")
            connection.execute("INSERT INTO metadata(key,value) VALUES ('vault_id',?)", (vault_id,))
            connection.execute("INSERT INTO metadata(key,value) VALUES ('storage_mode',?)", (STORAGE_MODE,))
            connection.execute("INSERT INTO metadata(key,value) VALUES ('policy_version',?)", (POLICY_VERSION,))
            now = now_iso()
            control_id = random_id("cap")
            connection.execute(
                "INSERT INTO capabilities(id,token_hash,project_id,provider,permissions_json,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (control_id, token_hash(control_token), None, "user_control", '["control","read"]', now),
            )
            created = []
            for spec in projects:
                project_id = random_id("prj")
                sequence = cls._next_sequence(connection)
                name = spec["name"]
                path_hint = spec["path_hint"]
                connection.execute(
                    "INSERT INTO projects(id,name,path_hint,created_at,created_seq) VALUES (?,?,?,?,?)",
                    (project_id, name, path_hint, now, sequence),
                )
                scope_id = random_id("scp")
                connection.execute(
                    "INSERT INTO scopes(id,project_id,kind,value) VALUES (?,?,?,?)",
                    (scope_id, project_id, "project", project_id),
                )
                cap_files = {}
                for provider in spec["providers"]:
                    cap_token = secrets.token_urlsafe(32)
                    cap_id = random_id("cap")
                    connection.execute(
                        "INSERT INTO capabilities(id,token_hash,project_id,provider,permissions_json,created_at) "
                        "VALUES (?,?,?,?,?,?)",
                        (cap_id, token_hash(cap_token), project_id, provider, '["propose","read"]', now),
                    )
                    cap_path = file_map["caps"] / ("%s.%s.cap" % (project_id, provider))
                    write_private(cap_path, _capability_document(project_id, provider, ["propose", "read"], cap_token))
                    cap_files[provider] = str(cap_path)
                created.append({"id": project_id, "scope_id": scope_id, "name": name, "capabilities": cap_files})
            event_seq = cls._next_sequence(connection)
            cls._append_audit_raw(
                connection,
                audit_key,
                event_seq,
                "user_control",
                "vault_initialized",
                vault_id,
                vault_id,
                "bootstrap",
                "ok",
                now,
            )
            connection.commit()
            ensure_private_regular(file_map["db"], "The vault database")
            cls._sync_audit_head_raw(connection, file_map["audit_head"])
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return {
                "vault_id": vault_id,
                "data_dir": str(data_dir),
                "socket": str(file_map["socket"]),
                "control_capability": str(file_map["control"]),
                "projects": created,
                "storage_mode": STORAGE_MODE,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _next_sequence(connection: sqlite3.Connection) -> int:
        connection.execute("UPDATE sequence SET value=value+1 WHERE singleton=1")
        return int(connection.execute("SELECT value FROM sequence WHERE singleton=1").fetchone()[0])

    def next_sequence(self) -> int:
        return self._next_sequence(self.connection)

    @staticmethod
    def _append_audit_raw(
        connection: sqlite3.Connection,
        audit_key: bytes,
        event_seq: int,
        actor_kind: str,
        operation: str,
        scoped_id: str,
        target_id: str,
        policy_decision: str,
        result: str,
        occurred_at: str,
    ) -> None:
        previous = connection.execute("SELECT mac FROM audit_events ORDER BY audit_seq DESC LIMIT 1").fetchone()
        previous_mac = previous[0] if previous else "GENESIS"
        payload = {
            "actor_kind": actor_kind,
            "event_seq": event_seq,
            "key_id": AUDIT_KEY_ID,
            "occurred_at": occurred_at,
            "operation": operation,
            "policy_decision": policy_decision,
            "result": result,
            "scoped_id": scoped_id,
            "target_id": target_id,
        }
        mac = hmac.new(
            audit_key,
            (previous_mac + "\n" + canonical_json(payload)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        connection.execute(
            "INSERT INTO audit_events(event_seq,actor_kind,operation,scoped_id,target_id,policy_decision,"
            "result,key_id,occurred_at,previous_mac,mac) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_seq,
                actor_kind,
                operation,
                scoped_id,
                target_id,
                policy_decision,
                result,
                AUDIT_KEY_ID,
                occurred_at,
                previous_mac,
                mac,
            ),
        )

    def append_audit(
        self,
        event_seq: int,
        actor_kind: str,
        operation: str,
        scoped_id: str,
        target_id: str,
        policy_decision: str = "allowed",
        result: str = "ok",
        occurred_at: Optional[str] = None,
    ) -> None:
        self._append_audit_raw(
            self.connection,
            self.audit_key,
            event_seq,
            actor_kind,
            operation,
            scoped_id,
            target_id,
            policy_decision,
            result,
            occurred_at or now_iso(),
        )

    def keyed_digest(self, domain: str, value: str) -> str:
        payload = domain.encode("ascii") + b"\x00" + value.encode("utf-8")
        return hmac.new(self.audit_key, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def _sync_audit_head_raw(connection: sqlite3.Connection, path: Path) -> None:
        row = connection.execute("SELECT audit_seq,mac FROM audit_events ORDER BY audit_seq DESC LIMIT 1").fetchone()
        value = {"audit_seq": int(row[0]) if row else 0, "mac": row[1] if row else "GENESIS"}
        encoded = (canonical_json(value) + "\n").encode("utf-8")
        if path_exists(path):
            replace_private(path, encoded)
        else:
            write_private(path, encoded)

    def sync_audit_head(self) -> None:
        # Reacquire the writer lock after the caller's SQL commit. Another writer
        # may have committed meanwhile: validate and publish the CURRENT head,
        # never a captured older head. Bootstrap alone may create a missing anchor.
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self._require_reconcilable_audit()
            self._sync_audit_head_raw(self.connection, self.files["audit_head"])
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def _require_reconcilable_audit(self) -> None:
        if self.verify_audit()["status"] not in {"valid", "external_anchor_stale"}:
            raise MemoryError("audit_recovery_refused", "The audit chain and existing anchor cannot be reconciled safely.")

    def begin(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")

    def commit(self, sync_audit: bool = False) -> None:
        if sync_audit:
            # Inspect the pending chain while still holding the mutation lock.
            # Never commit through a known missing, corrupt or ahead anchor.
            self._require_reconcilable_audit()
        self.connection.commit()
        if sync_audit:
            try:
                self.sync_audit_head()
            except (OSError, sqlite3.Error, MemoryError) as exc:
                # rollback() cannot undo this transaction. Keep the outcome
                # distinct from validation/pre-commit failure without leaking IO.
                raise CommittedAuditError() from exc

    def rollback(self) -> None:
        self.connection.rollback()

    def authenticate(self, token: str) -> Dict[str, Any]:
        row = self.connection.execute(
            "SELECT id,project_id,provider,permissions_json FROM capabilities "
            "WHERE token_hash=? AND revoked_at IS NULL",
            (token_hash(token),),
        ).fetchone()
        if not row:
            raise MemoryError("unauthorized", "The capability is invalid or revoked.")
        return {
            "id": row["id"],
            "project_id": row["project_id"],
            "provider": row["provider"],
            "permissions": json.loads(row["permissions_json"]),
            "token": token,
        }

    def verify_audit(self) -> Dict[str, Any]:
        # Audit rows and the filesystem head need a single writer-serialized view;
        # a plain read snapshot alone can race a newer writer's anchor publication.
        own_transaction = not self.connection.in_transaction
        if own_transaction:
            self.connection.execute("BEGIN IMMEDIATE")
        try:
            return self._verify_audit_locked()
        finally:
            if own_transaction:
                self.connection.rollback()

    def _verify_audit_locked(self) -> Dict[str, Any]:
        return verify_audit_snapshot(self.connection, self.audit_key,
            lambda: decode_frame(read_private(self.files["audit_head"], 1024)))

    def close(self) -> None:
        self.connection.close()


def load_capability(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(read_private(path).decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise MemoryError("invalid_capability_file", "The capability file could not be loaded.") from exc
    expected = {"schema_version", "project_id", "provider", "permissions", "token"}
    if set(value) != expected or value.get("schema_version") != 1:
        raise MemoryError("invalid_capability_file", "The capability file schema is invalid.")
    return value
