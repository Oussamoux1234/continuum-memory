"""Offline SQLCipher key rotation with authenticated, fail-closed recovery.

The daemon lock serializes cooperating processes. Neither it nor this journal
protects against another process with unrestricted access to the same UID.
Candidate recovery opens happen only on independent copies: opening a hot
rollback journal can write even before a query-only connection reads a page.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import tempfile
import time
from pathlib import Path

from . import storage
from .approval import LINUX_APPROVAL_BOUNDARY, approval_payload, linux_public_key, verify_payload
from .audit_validation import verify_audit_snapshot
from .broker import LinuxPolkitApprovalBroker
from .daemon_lock import DaemonLock
from .errors import MemoryError
from .security import (
    GRANT_TTL_SECONDS,
    ID_RE,
    _validate_open_regular,
    canonical_json,
    digest_json,
    ensure_private_directory,
    ensure_private_regular,
    path_exists,
    random_id,
    read_private,
    replace_private,
    write_private,
)
from .transport import decode_frame


MAX_JOURNAL_BYTES = 4096
APPLICATION_ID = 1129143636
ARTIFACT_SUFFIXES = ("", "-journal", "-wal", "-shm")
JOURNAL_FIELDS = {
    "schema_version", "storage_mode", "vault_id", "current_generation", "operation_id",
    "old_key_sha256", "new_key_sha256", "phase", "mac",
}
PHASES = {"preparing", "prepared", "published"}
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
MAC_DOMAIN = b"continuum-storage-rotation-v1\x00"
JOURNAL_MAGIC = bytes.fromhex("d9d505f920a163d7")
CONTROL_FILE_LIMITS = {
    "storage.key": 32, "storage.key.next": 32, "audit.key": 32,
    "audit.head": 1024, "storage.rotation.json": MAX_JOURNAL_BYTES,
}


def _refuse() -> None:
    raise MemoryError(
        "rotation_recovery_refused",
        "Storage rotation state could not be validated; preserved material requires investigation.",
    )


def _key_hash(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()


def _same_file(left, right) -> bool:
    return (
        left.st_dev, left.st_ino, left.st_size, left.st_mtime_ns, left.st_ctime_ns
    ) == (
        right.st_dev, right.st_ino, right.st_size, right.st_mtime_ns, right.st_ctime_ns
    )


def _fingerprint(path: Path, destination: Path | None = None) -> dict:
    """Hash/copy through no-follow descriptors and reject in-flight changes."""
    expected = ensure_private_regular(path, "Storage rotation material")
    maximum = CONTROL_FILE_LIMITS.get(path.name)
    if maximum is not None and expected.st_size > maximum:
        _refuse()
    if path.name in {"storage.key", "storage.key.next", "audit.key"} and expected.st_size != 32:
        _refuse()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(str(path), flags)
    output = None
    try:
        opened = _validate_open_regular(fd, "Storage rotation material")
        if not _same_file(expected, opened):
            _refuse()
        if destination is not None:
            ensure_private_directory(destination.parent)
            output = os.open(str(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            _validate_open_regular(output, "Storage rotation probe")
        digest = hashlib.sha256()
        size = 0
        tail = b""
        while True:
            chunk = os.read(fd, min(1024 * 1024, opened.st_size - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > opened.st_size:
                _refuse()
            digest.update(chunk)
            tail = (tail + chunk)[-8:]
            if output is not None:
                remaining = memoryview(chunk)
                while remaining:
                    count = os.write(output, remaining)
                    if count <= 0:
                        raise OSError("Storage probe copy failed")
                    remaining = remaining[count:]
        after = _validate_open_regular(fd, "Storage rotation material")
        current = ensure_private_regular(path, "Storage rotation material")
        if not _same_file(opened, after) or not _same_file(opened, current) or size != opened.st_size:
            _refuse()
        # SQLite's super-journal trailer ends with this magic. Such a journal
        # can reference paths outside the copied artifact set; never open it.
        # See src/pager.c readSuperJournal()/writeSuperJournal() upstream.
        if path.name.endswith("-journal") and size >= 16 and tail == JOURNAL_MAGIC:
            _refuse()
        return {
            "sha256": digest.hexdigest(), "size": size, "device": opened.st_dev,
            "inode": opened.st_ino, "mtime_ns": opened.st_mtime_ns, "ctime_ns": opened.st_ctime_ns,
        }
    finally:
        if output is not None:
            os.close(output)
        os.close(fd)


def _snapshot(data_dir: Path) -> dict:
    files = storage.paths(data_dir)
    ensure_private_directory(data_dir)
    required = ("db", "storage_key", "audit_key", "audit_head")
    for name in required:
        ensure_private_regular(files[name], "Storage rotation material")
    allowed = {files["db"].name + suffix for suffix in ARTIFACT_SUFFIXES}
    if any(path.name.startswith(files["db"].name) and path.name not in allowed for path in data_dir.iterdir()):
        _refuse()
    selected = [Path(str(files["db"]) + suffix) for suffix in ARTIFACT_SUFFIXES]
    selected.extend(files[name] for name in ("storage_key", "audit_key", "audit_head", "rotation_state", "next_storage_key"))
    return {path.name: _fingerprint(path) for path in selected if path_exists(path)}


def _unchanged(data_dir: Path, snapshot: dict) -> None:
    if _snapshot(data_dir) != snapshot:
        _refuse()


def _rotation_id(value) -> bool:
    return isinstance(value, str) and value.startswith("rot_") and ID_RE.fullmatch(value) is not None


def _journal_mac(state: dict, audit_key: bytes) -> str:
    payload = {key: value for key, value in state.items() if key != "mac"}
    return hmac.new(audit_key, MAC_DOMAIN + canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def _read_journal(data_dir: Path, audit_key: bytes) -> dict:
    try:
        state = decode_frame(read_private(storage.paths(data_dir)["rotation_state"], MAX_JOURNAL_BYTES))
    except (MemoryError, OSError, ValueError, RecursionError):
        _refuse()
    if not isinstance(state, dict) or set(state) != JOURNAL_FIELDS:
        _refuse()
    if (
        type(state["schema_version"]) is not int or state["schema_version"] != 1
        or state["storage_mode"] != storage.STORAGE_MODE
        or not isinstance(state["vault_id"], str) or not state["vault_id"].startswith("vlt_")
        or not ID_RE.fullmatch(state["vault_id"])
        or not _rotation_id(state["operation_id"])
        or not (state["current_generation"] == "initial" or _rotation_id(state["current_generation"]))
        or state["current_generation"] == state["operation_id"]
        or not isinstance(state["phase"], str) or state["phase"] not in PHASES
    ):
        _refuse()
    for field in ("old_key_sha256", "new_key_sha256", "mac"):
        if not isinstance(state[field], str) or not DIGEST_RE.fullmatch(state[field]):
            _refuse()
    if state["old_key_sha256"] == state["new_key_sha256"] or not hmac.compare_digest(state["mac"], _journal_mac(state, audit_key)):
        _refuse()
    return state


def _write_journal(data_dir: Path, state: dict, audit_key: bytes) -> None:
    state["mac"] = _journal_mac(state, audit_key)
    encoded = (canonical_json(state) + "\n").encode("utf-8")
    if len(encoded) > MAX_JOURNAL_BYTES:
        _refuse()
    path = storage.paths(data_dir)["rotation_state"]
    if path_exists(path):
        replace_private(path, encoded)
    else:
        write_private(path, encoded)
    storage._sync_private_directory(data_dir)


def _identity(connection) -> dict:
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    application = connection.execute("PRAGMA application_id").fetchone()[0]
    metadata = dict(connection.execute(
        "SELECT key,value FROM metadata WHERE key IN "
        "('vault_id','storage_mode','storage_generation','storage_rotation_operation')"
    ).fetchall())
    vault_id = metadata.get("vault_id")
    generation = metadata.get("storage_generation", "initial")
    operation = metadata.get("storage_rotation_operation")
    if (
        version != storage.SCHEMA_VERSION or version != 5 or application != APPLICATION_ID
        or metadata.get("storage_mode") != storage.STORAGE_MODE
        or not isinstance(vault_id, str) or not vault_id.startswith("vlt_") or not ID_RE.fullmatch(vault_id)
        or not (generation == "initial" or _rotation_id(generation))
        or (generation == "initial" and operation is not None)
        or (generation != "initial" and operation != generation)
    ):
        _refuse()
    return {"vault_id": vault_id, "generation": generation, "rotation_operation": operation}


def _integrity(connection) -> None:
    if (
        connection.execute("PRAGMA cipher_integrity_check").fetchall()
        or [row[0] for row in connection.execute("PRAGMA integrity_check")] != ["ok"]
        or connection.execute("PRAGMA foreign_key_check").fetchall()
    ):
        _refuse()


def _matching_rotation_event(connection, state: dict) -> bool:
    events = connection.execute(
        "SELECT actor_kind,scoped_id,target_id,policy_decision,result FROM audit_events "
        "WHERE operation='storage_key_rotated' AND target_id=?", (state["operation_id"],)
    ).fetchall()
    expected = ("user_control", state["vault_id"], state["operation_id"], "os_approved", "ok")
    return len(events) == 1 and tuple(events[0]) == expected


def _probe_candidates(
    data_dir: Path, candidates: list[bytes], snapshot: dict, state: dict | None = None,
) -> list[tuple[str, dict]]:
    """Each distinct key gets its own complete, independently recoverable copy."""
    valid = []
    distinct = {_key_hash(key): key for key in candidates}
    database = storage.paths(data_dir)["db"]
    for digest, key in distinct.items():
        with tempfile.TemporaryDirectory(prefix="continuum-rotation-probe-") as temporary:
            directory = Path(temporary)
            for suffix in ARTIFACT_SUFFIXES:
                source = Path(str(database) + suffix)
                if source.name in snapshot:
                    observed = _fingerprint(source, directory / source.name)
                    if observed != snapshot[source.name]:
                        _refuse()
                elif path_exists(source):
                    _refuse()
            for name in ("audit_key", "audit_head"):
                source = storage.paths(data_dir)[name]
                if _fingerprint(source, directory / source.name) != snapshot[source.name]:
                    _refuse()
            connection = None
            try:
                connection = storage._connect(directory / database.name, key)
                identity = _identity(connection)
                _integrity(connection)
                audit = verify_audit_snapshot(
                    connection,
                    read_private(directory / "audit.key", 32),
                    lambda: decode_frame(read_private(directory / "audit.head", 1024)),
                )
                committed_rotation = (
                    state is not None
                    and identity["vault_id"] == state["vault_id"]
                    and identity["generation"] == state["operation_id"]
                    and _matching_rotation_event(connection, state)
                )
                if state is not None:
                    _match_identity(identity, state, digest)
                    if identity["generation"] == state["operation_id"]:
                        if not committed_rotation:
                            _refuse()
                    elif connection.execute(
                        "SELECT 1 FROM audit_events WHERE operation='storage_key_rotated' "
                        "AND target_id=? LIMIT 1", (state["operation_id"],)
                    ).fetchone():
                        _refuse()
                if audit["status"] != "valid" and not (
                    audit["status"] == "external_anchor_stale" and committed_rotation
                ):
                    _refuse()
                valid.append((digest, identity))
            except (MemoryError, storage.sqlite3.Error):
                # A rejected copy is disposable; no candidate touches the original.
                pass
            finally:
                if connection is not None:
                    connection.close()
    _unchanged(data_dir, snapshot)
    return valid


def _match_identity(identity: dict, state: dict, selected_hash: str) -> None:
    if identity["vault_id"] != state["vault_id"]:
        _refuse()
    if selected_hash == state["old_key_sha256"]:
        if identity["generation"] != state["current_generation"] or state["phase"] == "published":
            _refuse()
    elif selected_hash == state["new_key_sha256"]:
        allowed = {state["current_generation"], state["operation_id"]}
        if identity["generation"] not in allowed or state["phase"] == "preparing":
            _refuse()
        if state["phase"] == "published" and identity["generation"] != state["operation_id"]:
            _refuse()
    else:
        _refuse()


def _require_unexpired(expires_at: int) -> None:
    if int(time.time()) > expires_at:
        raise MemoryError("approval_expired", "The operating-system approval expired.")


def _authorize(operation: str, state: dict, snapshot: dict, selected_key_sha256: str, outcome: str) -> int:
    caller_uid = os.getuid()
    public_key = linux_public_key(caller_uid)
    if public_key is None:
        raise MemoryError("approval_broker_unavailable", "A provisioned Linux approval broker is required.")
    preview = {
        "operation": operation, "vault_id": state["vault_id"],
        "storage_mode": state["storage_mode"],
        "rotation_operation_id": state["operation_id"], "current_generation": state["current_generation"],
        "old_key_sha256": state["old_key_sha256"], "new_key_sha256": state["new_key_sha256"],
        "phase": state["phase"], "journal_digest": digest_json(state),
        "selected_key_sha256": selected_key_sha256, "outcome": outcome,
        "material": snapshot,
    }
    nonce = random_id("gnt")
    expires_at = int(time.time()) + GRANT_TTL_SECONDS
    preview_digest = digest_json(preview)
    challenge = {
        "approval_boundary": LINUX_APPROVAL_BOUNDARY, "vault_id": state["vault_id"],
        "nonce": nonce, "operation": operation, "preview": preview,
        "preview_digest": preview_digest, "expires_at": expires_at,
        "confirmation": "Authorize this offline storage-key operation.",
    }
    grant = LinuxPolkitApprovalBroker().authorize(challenge)
    _require_unexpired(expires_at)
    payload = approval_payload(state["vault_id"], caller_uid, nonce, operation, preview_digest, expires_at)
    if digest_json(preview) != preview_digest or not verify_payload(public_key, payload, grant):
        raise MemoryError("approval_invalid", "The operating-system approval proof is invalid.")
    _require_unexpired(expires_at)
    return expires_at


def _sync_file(path: Path) -> None:
    expected = ensure_private_regular(path, "Storage rotation database")
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = _validate_open_regular(fd, "Storage rotation database")
        if not _same_file(expected, opened):
            _refuse()
        os.fsync(fd)
        if not _same_file(opened, ensure_private_regular(path, "Storage rotation database")):
            _refuse()
    finally:
        os.close(fd)


def _rekey_database(store: storage.Store, next_key: bytes) -> None:
    connection = store.connection
    checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    if not checkpoint or tuple(checkpoint) != (0, 0, 0):
        _refuse()
    mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
    if not mode or str(mode[0]).lower() != "delete":
        _refuse()
    if len(next_key) != storage.STORAGE_KEY_BYTES:
        _refuse()
    connection.execute('PRAGMA rekey = "x\'%s\'"' % next_key.hex())


def _publish_key(data_dir: Path, next_key: bytes) -> None:
    # Keep .next until the published journal is durable, so every crash has a key.
    replace_private(storage.paths(data_dir)["storage_key"], next_key)
    storage._sync_private_directory(data_dir)


def _write_next_key(data_dir: Path, next_key: bytes) -> None:
    write_private(storage.paths(data_dir)["next_storage_key"], next_key)
    storage._sync_private_directory(data_dir)


def _durable_next_key(data_dir: Path, next_key: bytes) -> None:
    path = storage.paths(data_dir)["next_storage_key"]
    if not hmac.compare_digest(storage._read_storage_key(path), next_key):
        _refuse()
    # Readable complete bytes do not establish durability after a failed fsync.
    # A retry must make both the inode and its directory entry durable again.
    _sync_file(path)
    storage._sync_private_directory(data_dir)


def _fsync_database(data_dir: Path) -> None:
    _sync_file(storage.paths(data_dir)["db"])
    storage._sync_private_directory(data_dir)


def _record_rotation(data_dir: Path, state: dict) -> None:
    store = storage.Store._open_during_rotation(data_dir)
    try:
        store.begin()
        try:
            identity = _identity(store.connection)
            _match_identity(identity, state, state["new_key_sha256"])
            events = store.connection.execute(
                "SELECT actor_kind,scoped_id,target_id,policy_decision,result FROM audit_events "
                "WHERE operation='storage_key_rotated' AND target_id=?", (state["operation_id"],)
            ).fetchall()
            if identity["generation"] == state["operation_id"]:
                expected = ("user_control", state["vault_id"], state["operation_id"], "os_approved", "ok")
                if len(events) != 1 or tuple(events[0]) != expected:
                    _refuse()
                store.rollback()
                # A prior commit may have succeeded before anchor publication failed.
                store.sync_audit_head()
            else:
                if events or state["phase"] == "published":
                    _refuse()
                if store.verify_audit()["status"] != "valid":
                    _refuse()
                for name in ("storage_generation", "storage_rotation_operation"):
                    store.connection.execute(
                        "INSERT INTO metadata(key,value) VALUES (?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (name, state["operation_id"])
                    )
                store.append_audit(
                    store.next_sequence(), "user_control", "storage_key_rotated",
                    state["vault_id"], state["operation_id"], policy_decision="os_approved",
                )
                store.commit(sync_audit=True)
            if store.verify_audit()["status"] != "valid":
                _refuse()
            _integrity(store.connection)
        except BaseException:
            store.rollback()
            raise
    finally:
        store.close()


def _cleanup(data_dir: Path) -> None:
    files = storage.paths(data_dir)
    for name in ("next_storage_key", "rotation_state"):
        path = files[name]
        if path_exists(path):
            ensure_private_regular(path, "Storage rotation material")
            path.unlink()
            storage._sync_private_directory(data_dir)


def _finish(
    data_dir: Path, state: dict, audit_key: bytes, next_key: bytes,
    selected_hash: str, lock: DaemonLock, proof_expires_at: int | None = None,
) -> dict:
    files = storage.paths(data_dir)
    lock.check()
    if selected_hash == state["old_key_sha256"]:
        if proof_expires_at is not None:
            _require_unexpired(proof_expires_at)
        _durable_next_key(data_dir, next_key)
        proof_expires_at = None  # The approved durable operation has begun.
        if state["phase"] == "preparing":
            state["phase"] = "prepared"
            _write_journal(data_dir, state, audit_key)
        store = storage.Store._open_during_rotation(data_dir)
        try:
            _match_identity(_identity(store.connection), state, selected_hash)
            if store.verify_audit()["status"] != "valid":
                _refuse()
            _rekey_database(store, next_key)
        finally:
            store.close()
    # Do not infer durability/key selection from a native rekey return alone.
    # It may have left a rollback journal. Re-prove the key on isolated copies
    # before any new-key open can replay pages in the original database.
    snapshot = _snapshot(data_dir)
    active = storage._read_storage_key(files["storage_key"])
    valid = _probe_candidates(data_dir, [active, next_key], snapshot, state)
    if len(valid) != 1 or valid[0][0] != state["new_key_sha256"]:
        _refuse()
    _match_identity(valid[0][1], state, state["new_key_sha256"])
    lock.check()
    if proof_expires_at is not None:
        _require_unexpired(proof_expires_at)
    connection = storage._connect(files["db"], next_key)
    try:
        _match_identity(_identity(connection), state, state["new_key_sha256"])
        _integrity(connection)
    finally:
        connection.close()
    _fsync_database(data_dir)
    lock.check()
    if path_exists(files["next_storage_key"]):
        _durable_next_key(data_dir, next_key)
    elif state["phase"] != "published":
        _refuse()
    if _key_hash(storage._read_storage_key(files["storage_key"])) != state["new_key_sha256"]:
        _publish_key(data_dir, next_key)
    else:
        # The previous attempt may have renamed the key and then failed its
        # directory fsync. Do not infer publication durability from visibility.
        _sync_file(files["storage_key"])
        storage._sync_private_directory(data_dir)
    _record_rotation(data_dir, state)
    lock.check()
    state["phase"] = "published"
    _write_journal(data_dir, state, audit_key)
    _cleanup(data_dir)
    return {"status": "rotated", "operation_id": state["operation_id"],
            "vault_id": state["vault_id"], "storage_generation": state["operation_id"]}


def rotate_storage_key(data_dir: Path) -> dict:
    """Create a fresh raw key, after fresh OS proof, while the daemon is stopped."""
    try:
        storage._require_sqlcipher_runtime()
        with DaemonLock(data_dir) as lock:
            files = storage.paths(data_dir)
            storage.require_no_pending_rotation(data_dir)
            lock.prepare_socket(files["socket"])
            snapshot = _snapshot(data_dir)
            active = storage._read_storage_key(files["storage_key"])
            audit_key = read_private(files["audit_key"], 32)
            if len(audit_key) != 32:
                _refuse()
            valid = _probe_candidates(data_dir, [active], snapshot)
            if len(valid) != 1:
                _refuse()
            selected_hash, identity = valid[0]
            next_key = secrets.token_bytes(storage.STORAGE_KEY_BYTES)
            if _key_hash(next_key) == selected_hash:
                _refuse()
            state = {
                "schema_version": 1, "storage_mode": storage.STORAGE_MODE, "vault_id": identity["vault_id"],
                "current_generation": identity["generation"], "operation_id": random_id("rot"),
                "old_key_sha256": selected_hash, "new_key_sha256": _key_hash(next_key),
                "phase": "preparing",
            }
            state["mac"] = _journal_mac(state, audit_key)
            expires_at = _authorize("rotate_storage_key", state, snapshot, selected_hash, "rotate")
            _unchanged(data_dir, snapshot)
            lock.check()
            _require_unexpired(expires_at)
            # Copied identity and audit validation precede approval. The first
            # original open/hardening must wait for durable prepared state.
            _write_journal(data_dir, state, audit_key)
            _write_next_key(data_dir, next_key)
            state["phase"] = "prepared"
            _write_journal(data_dir, state, audit_key)
            return _finish(data_dir, state, audit_key, next_key, selected_hash, lock)
    except MemoryError:
        raise
    except Exception:
        raise MemoryError("rotation_failed", "Storage rotation stopped; preserved state must be recovered before use.") from None


def recover_storage_key(data_dir: Path) -> dict:
    """Recover one authenticated pending operation; never guess a key in place."""
    try:
        storage._require_sqlcipher_runtime()
        with DaemonLock(data_dir) as lock:
            files = storage.paths(data_dir)
            lock.prepare_socket(files["socket"])
            snapshot = _snapshot(data_dir)
            if files["rotation_state"].name not in snapshot:
                _refuse()
            audit_key = read_private(files["audit_key"], 32)
            if len(audit_key) != 32:
                _refuse()
            state = _read_journal(data_dir, audit_key)
            active = storage._read_storage_key(files["storage_key"])
            active_hash = _key_hash(active)
            if active_hash not in {state["old_key_sha256"], state["new_key_sha256"]}:
                _refuse()
            next_key = None
            if files["next_storage_key"].name in snapshot:
                next_key = storage._read_storage_key(files["next_storage_key"])
                if _key_hash(next_key) != state["new_key_sha256"]:
                    _refuse()
            if state["phase"] == "preparing" and active_hash != state["old_key_sha256"]:
                _refuse()
            if state["phase"] == "prepared" and next_key is None:
                _refuse()
            if state["phase"] == "published" and active_hash != state["new_key_sha256"]:
                _refuse()
            candidates = [active] + ([next_key] if next_key is not None else [])
            valid = _probe_candidates(data_dir, candidates, snapshot, state)
            if len(valid) != 1:
                _refuse()
            selected_hash, identity = valid[0]
            _match_identity(identity, state, selected_hash)
            abort = state["phase"] == "preparing" and next_key is None
            expires_at = _authorize("recover_storage_key", state, snapshot, selected_hash, "abort_preparation" if abort else "complete_rotation")
            _unchanged(data_dir, snapshot)
            lock.check()
            _require_unexpired(expires_at)
            if abort:
                if selected_hash != state["old_key_sha256"]:
                    _refuse()
                # The copy already proved the unchanged old-key snapshot. Abort
                # only this preparation; never replay a preexisting hot journal.
                _cleanup(data_dir)
                return {"status": "aborted", "operation_id": state["operation_id"],
                        "vault_id": state["vault_id"], "storage_generation": state["current_generation"]}
            if next_key is None:
                next_key = active  # Only the already-published, uniquely valid new key may reach here.
            return _finish(data_dir, state, audit_key, next_key, selected_hash, lock, expires_at)
    except MemoryError:
        raise
    except Exception:
        raise MemoryError("rotation_failed", "Storage recovery stopped; preserved state requires investigation.") from None
