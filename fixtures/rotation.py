"""Synthetic rotation proofs and subprocess faults; never a human-approval path."""

import json
import os
import stat
import subprocess
import sys
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from continuum_memory import approval, storage
from continuum_memory.security import canonical_json
from tests.test_snapshot_forget import SnapshotForgetTest
from fixtures.key_custody import custody_fault


CANARY = "ROTATIONCANARYa541026cfa3991"
ARTIFACT_NAMES = ("continuum.db", "continuum.db-wal", "continuum.db-shm", "continuum.db-journal")
CRASH_EXIT = 73


def make_proof_keys(directory):
    directory.mkdir(mode=0o700)
    private = directory / "fixture-private.pem"
    public = directory / "fixture-public.pem"
    subprocess.run([str(approval.OPENSSL_PATH), "genpkey", "-algorithm", "RSA",
                    "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    subprocess.run([str(approval.OPENSSL_PATH), "pkey", "-in", str(private), "-pubout",
                    "-out", str(public)], check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=10)
    private.chmod(0o600)
    public.chmod(0o600)


def fixture_key_validator(path, _label):
    storage.ensure_private_regular(path)


class SyntheticBroker:
    """Signs real RSA proofs with fixture-owned keys, without claiming OS approval."""

    def __init__(self, directory, mutate=None):
        self.directory = Path(directory)
        self.mutate = mutate
        self.challenges = []
        self.grants = []

    def authorize(self, challenge):
        self.challenges.append(json.loads(canonical_json(challenge)))
        request = approval.approval_request(challenge)
        fields = {name: request[name] for name in
                  ("vault_id", "caller_uid", "nonce", "operation", "preview_digest", "expires_at")}
        if self.mutate is not None:
            self.mutate(fields, challenge)
        grant = approval.sign_payload(self.directory / "fixture-private.pem",
                                      approval.approval_payload(**fields),
                                      key_validator=fixture_key_validator)
        self.grants.append(grant)
        return grant


@contextmanager
def synthetic_approval(directory, broker=None):
    from continuum_memory import storage_rotation as rotation
    broker = broker or SyntheticBroker(directory)

    def verify(public_key, payload, grant):
        return approval.verify_payload(public_key, payload, grant,
                                       key_validator=fixture_key_validator)

    with ExitStack() as stack:
        stack.enter_context(patch.object(rotation, "linux_public_key",
                                         return_value=Path(directory) / "fixture-public.pem"))
        stack.enter_context(patch.object(rotation, "LinuxPolkitApprovalBroker", return_value=broker))
        stack.enter_context(patch.object(rotation, "verify_payload", side_effect=verify))
        yield broker


def file_snapshot(directory, *, database_only=False):
    """Capture source evidence without following an unsafe fixture symlink."""
    result = {}
    paths = [directory / name for name in ARTIFACT_NAMES] if database_only else directory.rglob("*")
    for path in paths:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        name = str(path.relative_to(directory))
        if name == "memoryd.lock":
            continue
        if stat.S_ISREG(info.st_mode):
            result[name] = (stat.S_IMODE(info.st_mode), path.read_bytes())
        elif stat.S_ISLNK(info.st_mode):
            result[name] = ("symlink", os.readlink(path))
    return result


def application_snapshot(connection):
    schema = [tuple(row) for row in connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")]
    tables = [row[1] for row in connection.execute("PRAGMA main.table_list")
              if row[2] in {"table", "virtual"}
              and not row[1].startswith("sqlite_")
              and row[1] not in {"audit_events", "sequence", "metadata"}]
    rows = {}
    for table in tables:
        quoted = '"' + table.replace('"', '""') + '"'
        columns = "rowid,*" if table == "assertion_fts" else "*"
        rows[table] = sorted((tuple(row) for row in connection.execute(
            "SELECT " + columns + " FROM " + quoted)), key=repr)
    return {"schema": schema, "rows": rows,
            "headers": tuple(connection.execute("PRAGMA " + name).fetchone()[0]
                             for name in ("user_version", "application_id"))}


class RotationVault:
    def __init__(self):
        self.fx = SnapshotForgetTest()
        self.fx.setUp()
        self.home = self.fx.home
        try:
            challenge = self.fx.kernel.admin_preview(self.fx.control, {
                "operation": "remember", "project": self.fx.project,
                "subject": "rotation retained", "claim": "Initial synthetic " + CANARY,
            })
            first = self.fx.apply(challenge)
            self.receipt_locator = {name: challenge[name] for name in ("nonce", "preview_digest")}
            self.receipt_result = self.fx.kernel.admin_result(self.fx.control, self.receipt_locator)["result"]
            self.live = self.fx.approve(operation="correct", target_id=first["assertion_id"],
                                        claim="Corrected synthetic " + CANARY)
            self.erased_delivery = {
                "subject": "rotation discarded", "claim": "Synthetic disposable item",
                "evidence": "Synthetic evidence", "source_handle": "fixture:discarded-rotation",
                "disclosure": ["codex"], "idempotency_key": "rotation-forgotten-delivery",
            }
            proposed = self.fx.kernel.propose(self.fx.codex, self.erased_delivery)
            discarded = self.fx.approve(operation="accept_proposal", proposal_id=proposed["proposal_id"])
            recalled = self.fx.kernel.search(self.fx.codex, {"query": discarded["assertion_id"]})
            self.fx.kernel.get(self.fx.codex, {"recall_id": recalled["recall_id"], "ids": [discarded["assertion_id"]]})
            self.fx.approve(operation="forget", target_id=discarded["assertion_id"])
            assert self.fx.store.connection.execute(
                "SELECT count(*) FROM proposal_tombstones WHERE proposal_id=? AND disposition='forgotten'",
                (proposed["proposal_id"],),
            ).fetchone()[0] == 1
            for name in ("pending", "rejected"):
                proposal = self.fx.kernel.propose(self.fx.codex, {
                    "subject": "rotation " + name, "claim": "Synthetic draft " + CANARY,
                    "evidence": "Synthetic evidence", "source_handle": "fixture:rotation",
                    "disclosure": ["codex"], "idempotency_key": "rotation-" + name,
                })
                if name == "rejected":
                    self.fx.approve(operation="reject_proposal", proposal_id=proposal["proposal_id"])
            self.fx.context(CANARY)
            self.vault_id = self.fx.store.vault_id
            self.application = application_snapshot(self.fx.store.connection)
            self.metadata = dict(self.fx.store.connection.execute("SELECT key,value FROM metadata"))
            self.audit_rows = [tuple(row) for row in self.fx.store.connection.execute(
                "SELECT * FROM audit_events ORDER BY audit_seq")]
            self.sequence = self.fx.store.connection.execute("SELECT value FROM sequence").fetchone()[0]
            self.receipts = [dict(row) for row in self.fx.store.connection.execute("SELECT * FROM admin_results")]
            self.old_key = storage.paths(self.home)["storage_key"].read_bytes()
            self.audit_key = storage.paths(self.home)["audit_key"].read_bytes()
            self.capabilities = {str(path.relative_to(self.home)): path.read_bytes()
                                 for path in self.home.rglob("*.cap")}
        except BaseException:
            self.fx.store.close()
            self.fx.temp.cleanup()
            raise
        else:
            self.fx.store.close()

    def close(self):
        self.fx.temp.cleanup()


def open_keyed_readonly(database, key):
    connection = storage.sqlite3.connect(database.resolve().as_uri() + "?mode=ro",
                                         uri=True, isolation_level=None)
    try:
        connection.execute('PRAGMA key = "x\'%s\'"' % key.hex())
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("SELECT count(*) FROM sqlite_schema").fetchone()
        return connection
    except BaseException:
        connection.close()
        raise


def create_hot_journal(data_dir, *, allow_unsupported=False):
    """Leave a real spilled, uncommitted SQLCipher transaction after process exit."""
    root = Path(__file__).resolve().parents[1]
    script = '''
import os, sys
from pathlib import Path
from continuum_memory import storage
home = Path(sys.argv[1])
if sys.argv[2] == "1":
    files = storage.paths(home)
    db = storage._connect(files["db"], storage._read_storage_key(files["storage_key"]), apply_hardening=True)
else:
    s = storage.Store(home)
    db = s.connection
assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
assert db.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
db.execute("PRAGMA cache_size=8")
db.execute("BEGIN IMMEDIATE")
for n in range(128):
    db.execute("INSERT INTO metadata(key,value) VALUES (?,?)",
               ("hot_fixture_%d" % n, "ROTATIONCANARYa541026cfa3991" + "x" * 8192))
os._exit(73)
'''
    return subprocess.run([sys.executable, "-c", script, str(data_dir), "1" if allow_unsupported else "0"],
                          capture_output=True, text=True, timeout=20,
                          env=dict(os.environ, PYTHONPATH=os.pathsep.join([str(root / "src"), str(root)]),
                                   PYTHONPYCACHEPREFIX=str(root / "work" / "pycache")))


@contextmanager
def boundary_fault(boundary, *, crash=False):
    """Wrap real operations; inject only at the requested persistence boundary."""
    from continuum_memory import storage_rotation as rotation
    fired = []
    recording = []

    def trigger(name):
        if name == boundary and not fired:
            fired.append(name)
            if crash:
                os._exit(CRASH_EXIT)
            raise OSError("Synthetic rotation boundary failure")

    def wrap(name, original):
        def invoke(*args, **kwargs):
            trigger(name + ":before")
            if name == "publish":
                with custody_fault(boundary, crash=crash) as custody_fired:
                    try:
                        result = original(*args, **kwargs)
                    finally:
                        fired.extend(custody_fired)
            else:
                result = original(*args, **kwargs)
            trigger(name + ":after")
            return result
        return invoke

    write_journal = rotation._write_journal
    record_rotation = rotation._record_rotation
    sync_anchor = storage.Store.sync_audit_head
    unlink = os.unlink

    def journal(data_dir, state, audit_key):
        result = write_journal(data_dir, state, audit_key)
        trigger("state:" + state["phase"])
        return result

    def record(*args, **kwargs):
        trigger("record:before")
        recording.append(True)
        try:
            result = record_rotation(*args, **kwargs)
        finally:
            recording.pop()
        trigger("record:after")
        return result

    def anchor(store):
        if recording:
            trigger("audit:after_commit")
        result = sync_anchor(store)
        if recording:
            trigger("audit:after_anchor")
        return result

    def remove(path, *args, **kwargs):
        result = unlink(path, *args, **kwargs)
        if Path(path).name == "storage.key.next":
            trigger("cleanup:next_unlinked")
        elif Path(path).name == "storage.rotation.json":
            trigger("cleanup:state_unlinked")
        return result

    with ExitStack() as stack:
        stack.enter_context(patch.object(rotation, "_write_journal", side_effect=journal))
        for function, name in (("_rekey_database", "rekey"), ("_publish_key", "publish"),
                               ("_write_next_key", "next"), ("_fsync_database", "database_sync")):
            stack.enter_context(patch.object(rotation, function, side_effect=wrap(name, getattr(rotation, function))))
        stack.enter_context(patch.object(rotation, "_record_rotation", side_effect=record))
        stack.enter_context(patch.object(storage.Store, "sync_audit_head", anchor))
        stack.enter_context(patch.object(os, "unlink", remove))
        yield fired


def main():
    from continuum_memory import storage_rotation as rotation
    action, home, proof_dir, boundary = sys.argv[1:]
    function = rotation.rotate_storage_key if action == "rotate" else rotation.recover_storage_key
    with synthetic_approval(Path(proof_dir)), boundary_fault(boundary, crash=True):
        result = function(Path(home))
    print(canonical_json(result))


if __name__ == "__main__":
    main()
