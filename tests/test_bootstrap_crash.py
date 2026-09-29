"""Bounded plaintext bootstrap crashes preserve residue and refuse partial use.

No interrupted initialization is repaired here. Synthetic IDs, tokens and time
make fixture copies comparable; SQLite, private writes and process exits are real.
This is not power-loss, native Windows, encryption or same-user isolation proof.
"""

import hashlib
import json
import os
import re
import select
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from continuum_memory import bootstrap_state, daemon, security, storage
from continuum_memory.errors import MemoryError
from continuum_memory.migrations import SCHEMA_SQL, SCHEMA_VERSION
from continuum_memory.security import canonical_json, create_private_directory, read_private, write_private
from continuum_memory.storage import Store, load_capability, paths


ROOT = Path(__file__).resolve().parents[1]
EXIT = 73
TIME = "2027-01-01T00:00:00Z"
VAULT_ID = "vlt_bootstrap_fixture_01"
PROJECTS = [
    {"name": name, "path_hint": "/synthetic/" + name, "providers": ["codex", "claude"]}
    for name in ("alpha", "beta")
]
MARKERS = ("bootstrap.claim", "bootstrap.complete")


def raw_inventory(home):
    """Observe without opening SQLite or following links; never retain key bytes."""
    result = {}
    for path in sorted(home.rglob("*")):
        info = path.lstat()
        kind = stat.S_IFMT(info.st_mode)
        digest = None
        if stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISLNK(info.st_mode):
            digest = hashlib.sha256(os.readlink(path).encode()).hexdigest()
        result[str(path.relative_to(home))] = (
            kind, stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink, info.st_dev, info.st_ino,
            info.st_size if not stat.S_ISDIR(info.st_mode) else None, digest,
        )
    return result


class BootstrapConnection:
    """Observe outer schema execution and each explicit bootstrap SQL mutation."""

    def __init__(self, connection, observer):
        self.connection = connection
        self.observer = observer

    def executescript(self, script):
        if script != SCHEMA_SQL:
            raise AssertionError("Unreviewed bootstrap schema script")
        self.observer.tick("before_schema_script")
        result = self.connection.executescript(script)
        self.observer.tick("after_schema_script")
        return result

    def execute(self, sql, *args, **kwargs):
        normalized = " ".join(sql.split())
        checkpoint = normalized == "PRAGMA wal_checkpoint(TRUNCATE)"
        if checkpoint:
            self.observer.tick("before_checkpoint")
        result = self.connection.execute(sql, *args, **kwargs)
        mutation = re.match(r"(UPDATE|INSERT(?: OR IGNORE)? INTO|DELETE FROM) ([a-z_]+)", normalized)
        if mutation:
            self.observer.tick("sql:" + mutation.group(2))
        elif normalized.startswith("PRAGMA user_version="):
            self.observer.tick("schema_version")
        elif normalized.split()[0] not in {"SELECT", "BEGIN", "PRAGMA"}:
            raise AssertionError("Unreviewed bootstrap SQL statement")
        if checkpoint:
            self.observer.tick("after_checkpoint")
        return result

    def commit(self):
        self.observer.tick("before_commit")
        self.connection.commit()
        self.observer.tick("after_commit")

    def close(self):
        self.observer.tick("before_close")
        self.connection.close()
        self.observer.tick("after_close")

    def cursor(self, *args, **kwargs):
        raise AssertionError("Bootstrap cursor bypasses the reviewed inventory")

    def executemany(self, *args, **kwargs):
        raise AssertionError("Bootstrap batch bypasses the reviewed inventory")

    def __getattr__(self, name):
        return getattr(self.connection, name)


class BootstrapObserver:
    def __init__(self, home, ordinal=0, race=False):
        self.home, self.ordinal, self.race = home, ordinal, race
        self.boundaries, self.live, self.writes = [], {}, Counter()
        self.real_open, self.real_close = os.open, os.close
        self.real_write, self.real_fsync = os.write, os.fsync
        self.real_connect, self.real_private = storage._connect, storage.write_private
        self.real_directory = storage.create_private_directory
        self.real_anchor = Store._sync_audit_head_raw
        self.real_verify = Store._verify_bootstrap

    def tick(self, label):
        self.boundaries.append(label)
        if len(self.boundaries) == self.ordinal:
            print(canonical_json({"ordinal": self.ordinal, "boundary": label}), flush=True)
            os._exit(EXIT)

    @staticmethod
    def identity(fd):
        value = os.fstat(fd)
        return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)

    def open(self, path, flags, *args, **kwargs):
        marker = str(Path(path).relative_to(self.home)) if isinstance(path, (str, Path)) and Path(path).parent == self.home else None
        observed = marker in MARKERS and bool(flags & os.O_CREAT)
        if observed and self.race and marker == "bootstrap.claim":
            print(canonical_json({"ready": True}), flush=True)
            if sys.stdin.buffer.read(1) != b"G":
                raise AssertionError("Concurrent bootstrap release missing")
        fd = self.real_open(path, flags, *args, **kwargs)
        if observed:
            if not flags & os.O_EXCL:
                raise AssertionError("Initialization record must use exclusive creation")
            self.live[fd] = (self.identity(fd), marker)
            self.tick(marker + ":created")
        return fd

    def close(self, fd):
        try:
            return self.real_close(fd)
        finally:
            self.live.pop(fd, None)

    def record_for(self, fd):
        tracked = self.live.get(fd)
        if tracked is None:
            return None
        if tracked[0] != self.identity(fd):
            raise AssertionError("Tracked initialization descriptor changed")
        return tracked[1]

    def write(self, fd, data):
        marker = self.record_for(fd)
        if marker is None:
            return self.real_write(fd, data)
        self.writes[marker] += 1
        if self.writes[marker] == 1:
            written = self.real_write(fd, data[:7])
            if not 0 < written < len(data):
                raise AssertionError("Marker did not reach a real partial write")
            self.tick(marker + ":partial")
            return written
        return self.real_write(fd, data)

    def fsync(self, fd):
        marker = self.record_for(fd)
        self.real_fsync(fd)
        if marker:
            self.tick(marker + ":synced")

    def private(self, path, data):
        result = self.real_private(path, data)
        if path.parent == self.home / "capabilities":
            label = "agent_capability"
        elif path.parent == self.home:
            label = path.name
        else:
            raise AssertionError("Unexpected bootstrap private file")
        self.tick("file:" + label)
        return result

    def directory(self, path, *args, **kwargs):
        result = self.real_directory(path, *args, **kwargs)
        if path != self.home / "capabilities":
            raise AssertionError("Unexpected bootstrap directory")
        self.tick("directory:capabilities")
        return result

    def connect(self, *args, **kwargs):
        self.tick("before_database_open")
        connection = self.real_connect(*args, **kwargs)
        self.tick("after_database_open")
        return BootstrapConnection(connection, self)

    def anchor(self, connection, path):
        self.tick("before_anchor")
        self.real_anchor(connection, path)
        self.tick("after_anchor")

    def verify(self, *args):
        self.tick("before_readback")
        self.real_verify(*args)
        self.tick("after_readback")

    def install(self, stack):
        for name in ("open", "close", "write", "fsync"):
            stack.enter_context(patch.object(security.os, name, side_effect=getattr(self, name)))
        stack.enter_context(patch.object(storage, "write_private", side_effect=self.private))
        stack.enter_context(patch.object(storage, "create_private_directory", side_effect=self.directory))
        stack.enter_context(patch.object(storage, "_connect", side_effect=self.connect))
        stack.enter_context(patch.object(Store, "_sync_audit_head_raw", side_effect=self.anchor))
        stack.enter_context(patch.object(Store, "_verify_bootstrap", side_effect=self.verify))


def bootstrap_child(home, ordinal=0, race=False):
    observed = BootstrapObserver(home, ordinal, race)
    ids, tokens = Counter(), Counter()

    def identifier(prefix):
        ids[prefix] += 1
        return "%s_bootstrap_fixture_%02d" % (prefix, ids[prefix])

    def token(_size):
        tokens["token"] += 1
        return "synthetic_bootstrap_token_%048d" % tokens["token"]

    with ExitStack() as stack:
        observed.install(stack)
        stack.enter_context(patch.object(storage, "random_id", side_effect=identifier))
        stack.enter_context(patch.object(storage, "now_iso", return_value=TIME))
        stack.enter_context(patch.object(storage.secrets, "token_bytes", return_value=b"B" * 32))
        stack.enter_context(patch.object(storage.secrets, "token_urlsafe", side_effect=token))
        try:
            result = Store.bootstrap(home, PROJECTS)
        except MemoryError as error:
            if not race:
                raise
            print(canonical_json({"error": error.code}), flush=True)
            return 2
        observed.tick("response_ready")
        if ids != {"vlt": 1, "cap": 5, "prj": 2, "scp": 2} or tokens != {"token": 5}:
            raise AssertionError("Unexpected bootstrap identifier inventory")
        if observed.live:
            raise AssertionError("Marker descriptor was not closed")
        print(canonical_json({"boundaries": observed.boundaries, "vault_id": result["vault_id"]}), flush=True)
        return 0


# Exact outer-call inventory for two projects and two providers each. Schema
# script internals, VFS instructions and native filesystem internals are excluded.
BOUNDARIES = [
    "bootstrap.claim:created", "bootstrap.claim:partial", "bootstrap.claim:synced",
    "directory:capabilities", "file:audit.key", "file:control.cap", "file:continuum.db",
    "before_database_open", "after_database_open", "before_schema_script", "after_schema_script", "schema_version",
    "sql:metadata", "sql:metadata", "sql:metadata", "sql:metadata", "sql:capabilities",
    "sql:sequence", "sql:projects", "sql:scopes", "sql:capabilities", "file:agent_capability",
    "sql:capabilities", "file:agent_capability",
    "sql:sequence", "sql:projects", "sql:scopes", "sql:capabilities", "file:agent_capability",
    "sql:capabilities", "file:agent_capability", "sql:sequence", "sql:audit_events",
    "before_commit", "after_commit", "before_anchor", "file:audit.head", "after_anchor",
    "before_readback", "after_readback", "before_checkpoint", "after_checkpoint", "before_close", "after_close",
    "bootstrap.complete:created", "bootstrap.complete:partial", "bootstrap.complete:synced", "response_ready",
]


@unittest.skipIf(os.name == "nt", "POSIX bootstrap process-crash fixture; native Windows gate is separate")
class BootstrapCrashTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-bootstrap-crash-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.environment = dict(os.environ, PYTHONPATH=os.pathsep.join((str(ROOT / "src"), str(ROOT))),
                                PYTHONWARNINGS="error::ResourceWarning")

    def home(self, name):
        home = self.root / name
        create_private_directory(home)
        return home

    def child(self, home, ordinal=0):
        completed = subprocess.run([sys.executable, "-m", "tests.test_bootstrap_crash", "--child",
                                    str(home), str(ordinal)], capture_output=True, env=self.environment, timeout=20)
        self.assertEqual(completed.stderr, b"")
        self.assertLess(len(completed.stdout), 32768)
        self.assertEqual(completed.returncode, EXIT if ordinal else 0)
        return json.loads(completed.stdout)

    def assert_complete(self, home):
        self.assertEqual(bootstrap_state.read_initialization_state(home), VAULT_ID)
        with_store = Store(home)
        try:
            db = with_store.connection
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual(dict(db.execute("SELECT key,value FROM metadata")), {
                "vault_id": VAULT_ID, "storage_mode": "plaintext_prototype",
                "policy_version": storage.POLICY_VERSION, "bootstrap_protocol": "1"})
            self.assertEqual([tuple(row) for row in db.execute(
                "SELECT id,name,path_hint,created_at,created_seq FROM projects ORDER BY created_seq")],
                [("prj_bootstrap_fixture_01", "alpha", "/synthetic/alpha", TIME, 1),
                 ("prj_bootstrap_fixture_02", "beta", "/synthetic/beta", TIME, 2)])
            self.assertEqual(db.execute("SELECT value FROM sequence").fetchone()[0], 3)
            self.assertEqual([tuple(row) for row in db.execute("SELECT id,project_id,kind,value FROM scopes ORDER BY id")],
                [("scp_bootstrap_fixture_01", "prj_bootstrap_fixture_01", "project", "prj_bootstrap_fixture_01"),
                 ("scp_bootstrap_fixture_02", "prj_bootstrap_fixture_02", "project", "prj_bootstrap_fixture_02")])
            expected_capabilities = []
            principals = [(None, "user_control")] + [("prj_bootstrap_fixture_%02d" % project, provider)
                for project in (1, 2) for provider in ("claude", "codex")]
            for number, (project, provider) in enumerate(principals, 1):
                digest = hashlib.sha256(("synthetic_bootstrap_token_%048d" % number).encode()).hexdigest()
                expected_capabilities.append(("cap_bootstrap_fixture_%02d" % number, digest, project, provider,
                    '["control","read"]' if project is None else '["propose","read"]', TIME, None))
            self.assertEqual([tuple(row) for row in db.execute(
                "SELECT id,token_hash,project_id,provider,permissions_json,created_at,revoked_at FROM capabilities ORDER BY id")],
                expected_capabilities)
            self.assertEqual(hashlib.sha256(read_private(paths(home)["audit_key"])).hexdigest(),
                             hashlib.sha256(b"B" * 32).hexdigest())
            self.assertEqual([tuple(row) for row in db.execute(
                "SELECT event_seq,actor_kind,operation,scoped_id,target_id,policy_decision,result,occurred_at FROM audit_events")],
                [(3, "user_control", "vault_initialized", VAULT_ID, VAULT_ID, "bootstrap", "ok", TIME)])
            self.assertEqual(with_store.verify_audit()["status"], "valid")
            self.assertEqual([tuple(row) for row in db.execute("PRAGMA integrity_check")], [("ok",)])
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            for table in ("assertion_versions", "evidence", "proposals", "recalls", "feedback", "admin_challenges", "admin_results"):
                self.assertEqual(db.execute("SELECT count(*) FROM " + table).fetchone()[0], 0)
            control = with_store.authenticate(load_capability(paths(home)["control"])["token"])
            self.assertEqual((control["provider"], control["project_id"], control["permissions"]),
                             ("user_control", None, ["control", "read"]))
            capabilities = sorted(paths(home)["caps"].glob("*.cap"))
            self.assertEqual(len(capabilities), 4)
            identities = set()
            for capability_path in capabilities:
                document = load_capability(capability_path)
                capability = with_store.authenticate(document["token"])
                self.assertEqual(capability["permissions"], ["propose", "read"])
                self.assertEqual(capability["project_id"], document["project_id"])
                self.assertEqual(capability["provider"], document["provider"])
                identities.add((capability["project_id"], capability["provider"]))
            self.assertEqual(identities, {(row[0], provider) for row in db.execute("SELECT id FROM projects")
                                           for provider in ("claude", "codex")})
            return tuple(db.iterdump())
        finally:
            with_store.close()

    def assert_incomplete_untouched(self, home, before):
        for _ in range(2):
            for operation, codes in (
                (lambda: bootstrap_state.read_initialization_state(home), {"initialization_incomplete"}),
                (lambda: Store(home), {"initialization_incomplete"}),
                (lambda: Store.bootstrap(home, PROJECTS), {"initialization_incomplete", "already_initialized"}),
                (lambda: daemon.serve(home), {"initialization_incomplete"}),
            ):
                with self.assertRaises(MemoryError) as caught:
                    operation()
                self.assertIn(caught.exception.code, codes)
                self.assertEqual(raw_inventory(home), before)

    def test_every_reviewed_bootstrap_boundary_refuses_partial_vault_or_opens_complete(self):
        reference = self.home("complete")
        recorded = self.child(reference)
        self.assertTrue(BOUNDARIES, "Bootstrap source inventory must be reviewed before execution")
        self.assertEqual(recorded, {"boundaries": BOUNDARIES, "vault_id": VAULT_ID})
        expected = self.assert_complete(reference)
        for ordinal, label in enumerate(BOUNDARIES, 1):
            with self.subTest(ordinal=ordinal, boundary=label):
                home = self.home("crash-%02d" % ordinal)
                self.assertEqual(self.child(home, ordinal), {"ordinal": ordinal, "boundary": label})
                before = raw_inventory(home)
                # A fully flushed completion record is the last published state.
                complete = ordinal >= BOUNDARIES.index("bootstrap.complete:synced") + 1
                if not complete:
                    self.assert_incomplete_untouched(home, before)
                else:
                    self.assertEqual(self.assert_complete(home), expected)
                    self.assertEqual(self.assert_complete(home), expected)
                    stable = raw_inventory(home)
                    for _ in range(2):
                        with self.assertRaises(MemoryError) as caught:
                            Store.bootstrap(home, PROJECTS)
                        self.assertEqual(caught.exception.code, "already_initialized")
                        self.assertEqual(raw_inventory(home), stable)

    def test_pending_and_unsafe_records_refuse_before_keys_database_or_endpoints(self):
        for kind in ("empty", "partial", "unknown", "complete_only", "symlink", "directory", "fifo", "hardlink"):
            with self.subTest(kind=kind):
                home = self.home("record-" + kind)
                claim = home / MARKERS[0]
                if kind == "directory":
                    create_private_directory(claim)
                elif kind == "fifo":
                    os.mkfifo(claim, 0o600)
                elif kind == "symlink":
                    claim.symlink_to("missing-fixture")
                elif kind == "complete_only":
                    write_private(home / MARKERS[1], b"{}")
                else:
                    write_private(claim, {"empty": b"", "partial": b'{"version":', "unknown": b"{}",
                                          "hardlink": b"fixture"}[kind])
                    if kind == "hardlink":
                        os.link(claim, home / "retained-alias")
                before = raw_inventory(home)
                with patch.object(storage, "read_private", side_effect=AssertionError("Audit key read before admission")), \
                        patch.object(storage, "_connect", side_effect=AssertionError("SQLite open before admission")), \
                        patch.object(daemon, "DaemonLock", side_effect=AssertionError("Daemon endpoint action before admission")):
                    self.assert_incomplete_untouched(home, before)

    def test_daemon_preendpoint_recheck_closes_absent_marker_race(self):
        empty = self.home("daemon-empty")
        with patch.object(daemon, "DaemonLock", side_effect=AssertionError("Empty home acquired a lock")), \
                patch.object(daemon, "Store", side_effect=AssertionError("Empty home opened Store")):
            with self.assertRaises(MemoryError) as caught:
                daemon.serve(empty)
        self.assertEqual(caught.exception.code, "not_initialized")
        self.assertEqual(raw_inventory(empty), {})
        for database_appears in (False, True):
            with self.subTest(database_appears=database_appears):
                home = self.home("daemon-race-" + str(database_appears))
                calls, published = [], {}

                def interleaved_check(directory):
                    calls.append(directory)
                    state = bootstrap_state.read_initialization_state(directory)
                    if len(calls) == 1:
                        self.assertIsNone(state)
                        # A cooperating initializer wins after the daemon's
                        # first observation but before its endpoint actions.
                        bootstrap_state.claim_initialization(home, VAULT_ID)
                        if database_appears:
                            write_private(paths(home)["db"], b"")
                        published.update(raw_inventory(home))
                    return state

                with patch.object(daemon, "read_initialization_state", side_effect=interleaved_check), \
                        patch.object(daemon, "DaemonLock", side_effect=AssertionError("Endpoint action crossed pending init")), \
                        patch.object(daemon, "Store", side_effect=AssertionError("Store opened before endpoint guard")):
                    with self.assertRaises(MemoryError) as caught:
                        daemon.serve(home)
                self.assertEqual(caught.exception.code,
                                 "initialization_incomplete" if database_appears else "not_initialized")
                self.assertEqual(len(calls), 2 if database_appears else 1)
                self.assertEqual(raw_inventory(home), published)

    def test_invalid_admission_and_orphan_sidecars_preserve_existing_directory(self):
        for suffix in ("-wal", "-shm", "-journal"):
            home = self.home("orphan" + suffix)
            write_private(Path(str(paths(home)["db"]) + suffix), b"retained synthetic residue")
            before = raw_inventory(home)
            with self.assertRaises(MemoryError) as caught:
                Store.bootstrap(home, PROJECTS)
            self.assertEqual(caught.exception.code, "already_initialized")
            self.assertEqual(raw_inventory(home), before)
        for index, project in enumerate((dict(PROJECTS[0], providers=["user_control"]),
                                          dict(PROJECTS[0], name=""))):
            home = self.home("invalid-%d" % index)
            before = raw_inventory(home)
            with self.assertRaises(MemoryError):
                Store.bootstrap(home, [project])
            self.assertEqual(raw_inventory(home), before)
        home = self.home("policy")
        write_private(home / "admission-policy.json", canonical_json({"version": 1, "deny_literals": ["alpha"]}).encode())
        before = raw_inventory(home)
        with self.assertRaises(MemoryError) as caught:
            Store.bootstrap(home, PROJECTS)
        self.assertEqual(caught.exception.code, "secret_rejected")
        self.assertEqual(raw_inventory(home), before)

    def test_lost_records_do_not_reclassify_flagged_vault_as_legacy(self):
        home = self.home("lost-records")
        self.child(home)
        for name in MARKERS:
            (home / name).unlink()  # Explicit synthetic accidental-loss fixture.
        before = raw_inventory(home)
        with patch.object(storage, "_configure_connection", side_effect=AssertionError("Admission configured database")), \
                patch.object(storage, "migrate", side_effect=AssertionError("Admission migrated database")):
            for _ in range(2):
                with self.assertRaises(MemoryError) as caught:
                    Store(home)
                self.assertEqual(caught.exception.code, "initialization_incomplete")
                self.assertEqual(raw_inventory(home), before)

    def test_metadata_identity_and_schema_refuse_before_configuration_or_migration(self):
        cases = {
            "missing-flag": ("DELETE FROM metadata WHERE key='bootstrap_protocol'", "initialization_incomplete"),
            "unknown-flag": ("UPDATE metadata SET value='2' WHERE key='bootstrap_protocol'", "initialization_incomplete"),
            "different-vault": ("UPDATE metadata SET value='vlt_other_fixture' WHERE key='vault_id'", "initialization_incomplete"),
            "unsupported-schema": ("PRAGMA user_version=999", "schema_mismatch"),
        }
        for name, (mutation, code) in cases.items():
            with self.subTest(name=name):
                home = self.home("metadata-" + name)
                self.child(home)
                connection = sqlite3.connect(paths(home)["db"])
                try:
                    connection.execute(mutation)  # Explicit synthetic damaged completed fixture.
                    connection.commit()
                finally:
                    connection.close()
                before = raw_inventory(home)
                with patch.object(storage, "_configure_connection", side_effect=AssertionError("Admission configured database")), \
                        patch.object(storage, "migrate", side_effect=AssertionError("Admission migrated database")):
                    for _ in range(2):
                        with self.assertRaises(MemoryError) as caught:
                            Store(home)
                        self.assertEqual(caught.exception.code, code)
                        self.assertEqual(raw_inventory(home), before)

    def test_invalid_record_pairs_refuse_without_database_access(self):
        valid = {"version": 1, "kind": "complete", "vault_id": VAULT_ID}
        invalid = [dict(valid, version=value) for value in (True, "1", 2)]
        invalid.extend((dict(valid, extra="unexpected"), dict(valid, kind="claim"),
                        dict(valid, vault_id="prj_wrong_kind"), dict(valid, vault_id="vlt_other_fixture")))
        for index, complete in enumerate(invalid):
            with self.subTest(index=index):
                home = self.home("pair-%d" % index)
                write_private(home / MARKERS[0], canonical_json(dict(valid, kind="claim")).encode())
                write_private(home / MARKERS[1], canonical_json(complete).encode())
                before = raw_inventory(home)
                with patch.object(storage, "_connect", side_effect=AssertionError("SQLite opened for invalid records")):
                    self.assert_incomplete_untouched(home, before)
        invalid_bytes = {
            "duplicate": b'{"version":1,"version":1,"kind":"complete","vault_id":"vlt_bootstrap_fixture_01"}',
            "oversize": b" " * (bootstrap_state.MAX_RECORD_BYTES + 1),
            "permissions": canonical_json(valid).encode(),
        }
        for name, data in invalid_bytes.items():
            with self.subTest(name=name):
                home = self.home("malformed-" + name)
                write_private(home / MARKERS[0], canonical_json(dict(valid, kind="claim")).encode())
                write_private(home / MARKERS[1], data)
                if name == "permissions":
                    (home / MARKERS[1]).chmod(0o644)
                before = raw_inventory(home)
                with patch.object(storage, "_connect", side_effect=AssertionError("SQLite opened for malformed records")):
                    self.assert_incomplete_untouched(home, before)

    def test_structural_readback_failure_never_publishes_completion(self):
        original_verify = Store._verify_bootstrap
        for defect in ("capability", "anchor", "metadata"):
            with self.subTest(defect=defect):
                home = self.home("readback-" + defect)

                def corrupt_then_verify(connection, files, *args):
                    if defect == "capability":
                        security.replace_private(files["control"], b"{}")
                    elif defect == "anchor":
                        security.replace_private(files["audit_head"], b"{}")
                    else:
                        connection.execute("UPDATE metadata SET value='fixture-wrong' WHERE key='policy_version'")
                    return original_verify(connection, files, *args)

                with patch.object(Store, "_verify_bootstrap", side_effect=corrupt_then_verify):
                    with self.assertRaises(MemoryError) as caught:
                        Store.bootstrap(home, PROJECTS)
                self.assertEqual(caught.exception.code, "initialization_incomplete")
                self.assertFalse((home / MARKERS[1]).exists())
                self.assert_incomplete_untouched(home, raw_inventory(home))

    def test_completed_new_vault_missing_anchor_does_not_reconstruct_trust(self):
        home = self.home("new-missing-anchor")
        self.child(home)
        paths(home)["audit_head"].unlink()  # Explicit synthetic damage after completion.
        self.assertEqual(bootstrap_state.read_initialization_state(home), VAULT_ID)
        opened = Store(home)
        try:
            self.assertEqual(opened.verify_audit()["status"], "anchor_unavailable")
            with self.assertRaises(MemoryError) as caught:
                opened.sync_audit_head()
            self.assertEqual(caught.exception.code, "audit_recovery_refused")
            self.assertFalse(paths(home)["audit_head"].exists())
        finally:
            opened.close()

    def test_legacy_admission_and_missing_anchor_diagnostics_remain_unchanged(self):
        home = self.home("legacy")
        self.child(home)
        # Explicit synthetic pre-protocol vault; no new migration or repair API.
        connection = sqlite3.connect(paths(home)["db"])
        try:
            connection.execute("DELETE FROM metadata WHERE key='bootstrap_protocol'")
            connection.commit()
        finally:
            connection.close()
        for name in MARKERS:
            (home / name).unlink()
        self.assertIsNone(bootstrap_state.read_initialization_state(home))
        opened = Store(home)
        try:
            self.assertEqual(opened.verify_audit()["status"], "valid")
            self.assertIsNone(opened.connection.execute(
                "SELECT value FROM metadata WHERE key='bootstrap_protocol'").fetchone())
            self.assertTrue(all(not (home / name).exists() for name in MARKERS))
        finally:
            opened.close()
        paths(home)["audit_head"].unlink()  # Missing anchor must never be rebuilt.
        opened = Store(home)
        try:
            self.assertEqual(opened.verify_audit()["status"], "anchor_unavailable")
            with self.assertRaises(MemoryError) as caught:
                opened.sync_audit_head()
            self.assertEqual(caught.exception.code, "audit_recovery_refused")
            self.assertFalse(paths(home)["audit_head"].exists())
        finally:
            opened.close()

    def test_concurrent_claim_reservation_has_one_winner_without_overwrite(self):
        home = self.home("concurrent")
        processes = []
        try:
            for _ in range(2):
                process = subprocess.Popen([sys.executable, "-m", "tests.test_bootstrap_crash", "--race", str(home)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment)
                processes.append(process)
            for process in processes:
                ready, _, _ = select.select([process.stdout], [], [], 10)
                self.assertTrue(ready, "Concurrent initializer did not reach the claim barrier")
                self.assertEqual(json.loads(process.stdout.readline()), {"ready": True})
            for process in processes:
                process.stdin.write(b"G")
                process.stdin.flush()
            outputs = []
            for process in processes:
                out, err = process.communicate(timeout=20)
                self.assertEqual(err, b"")
                outputs.append((process.returncode, json.loads(out)))
            self.assertEqual(sorted(code for code, _ in outputs), [0, 2])
            error = next(result for code, result in outputs if code == 2)
            self.assertIn(error["error"], {"initialization_incomplete", "already_initialized"})
            self.assert_complete(home)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                for pipe in (process.stdin, process.stdout, process.stderr):
                    if pipe:
                        pipe.close()


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--child":
        raise SystemExit(bootstrap_child(Path(sys.argv[2]), int(sys.argv[3])))
    if len(sys.argv) == 3 and sys.argv[1] == "--race":
        raise SystemExit(bootstrap_child(Path(sys.argv[2]), race=True))
    unittest.main()
