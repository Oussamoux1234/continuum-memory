"""Real process exits at every schema-upgrade statement/commit boundary.

Only synthetic private temporary databases are used. This tests process-crash
atomicity, not host power-loss durability or an encrypted storage provider.
"""

import os
import select
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from continuum_memory.migrations import SCHEMA_VERSION, migrate


ROOT = Path(__file__).resolve().parents[1]
CRASH_EXIT = 73


def connect(path):
    db = sqlite3.connect(str(path), timeout=10, isolation_level=None)
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db


def snapshot(db):
    # Logical comparison includes FTS shadow tables and every row. Filesystem
    # bytes (WAL salts/checkpoint layout) are not logical database state.
    return (db.execute("PRAGMA user_version").fetchone()[0],
            db.execute("PRAGMA application_id").fetchone()[0], tuple(db.iterdump()))


class BoundaryConnection:
    """Delegate real SQLite operations; inject exits without Python cleanup."""

    def __init__(self, connection, crash_after=None, mode=None):
        self.connection = connection
        self.crash_after = crash_after
        self.mode = mode
        self.boundaries = []

    def tick(self, label):
        self.boundaries.append(label)
        if self.crash_after == len(self.boundaries):
            os._exit(CRASH_EXIT)

    def execute(self, sql, *args):
        if self.mode == "follower" and sql == "BEGIN IMMEDIATE":
            print("waiting", flush=True)
        result = self.connection.execute(sql, *args)
        self.tick("execute:" + sql)
        if self.mode == "leader" and sql == "BEGIN IMMEDIATE":
            print("locked", flush=True)
            if sys.stdin.readline().strip() != "continue":
                raise RuntimeError("Synthetic migration barrier was not released")
        return result

    def commit(self):
        self.tick("before_commit")
        self.connection.commit()
        self.tick("after_commit")

    def rollback(self):
        self.connection.rollback()


def seed(path, version):
    db = connect(path)
    try:
        db.executescript((ROOT / ("tests/fixtures/schema-v%d.sql" % version)).read_text())
        db.execute("PRAGMA user_version=%d" % version)
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO metadata VALUES ('vault_id','vlt_migration_fixture')")
        db.execute("INSERT INTO projects VALUES ('prj_migration','synthetic','/synthetic','2027-01-01',1)")
        db.execute("INSERT INTO scopes VALUES ('scp_migration','prj_migration','project','prj_migration')")
        for provider in ("codex", "claude"):
            db.execute("INSERT INTO capabilities VALUES (?,?,'prj_migration',?,'[\"read\"]','2027-01-01',NULL)",
                       ("cap_" + provider, "synthetic-" + provider, provider))
        db.execute("INSERT INTO claim_threads VALUES ('mem_migration','prj_migration','scp_migration',"
                   "'database','database','2027-01-01',2)")
        for index, provider in enumerate(("codex", "claude", "*"), 3):
            assertion = "asr_migration_%d" % index
            db.execute("INSERT INTO assertion_versions(id,thread_id,project_id,body,admission,epistemic,"
                       "lifecycle,authority,classification,retention,valid_precision,recorded_at,ingest_seq,created_by) "
                       "VALUES (?,'mem_migration','prj_migration','synthetic migration canary','accepted',"
                       "'asserted','active','data','internal','forever','unknown','2027-01-01',?,'fixture')",
                       (assertion, index))
            db.execute("INSERT INTO assertion_disclosures VALUES (?,?)", (assertion, provider))
            db.execute("INSERT INTO assertion_fts VALUES (?,'prj_migration','database','synthetic migration canary')",
                       (assertion,))
        db.execute("UPDATE sequence SET value=5")
        db.execute("INSERT INTO recalls(id,project_id,provider,query_digest,result_ids_json,watermark,"
                   "allows_historical,created_at) VALUES ('rcl_migration','prj_migration','codex','opaque',"
                   "'[\"asr_migration_3\"]',5,1,'2027-01-01')")
        db.commit()
    finally:
        db.close()


class MigrationProcessCrashTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="continuum-migration-crash-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"))

    def command(self, path, version, point):
        return [sys.executable, str(Path(__file__).resolve()), "--migration-child", str(path),
                str(version), str(point)]

    def assert_integrity(self, db):
        self.assertEqual(db.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
        self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_each_statement_and_commit_crash_recovers_one_complete_state(self):
        for version in (2, 3, 4):
            template = self.home / ("template-%d.db" % version)
            expected_path = self.home / ("expected-%d.db" % version)
            seed(template, version)
            # All fixture handles are closed/checkpointed before these copies.
            shutil.copyfile(template, expected_path)
            db = connect(expected_path)
            try:
                original = snapshot(db)
                recorder = BoundaryConnection(db)
                self.assertEqual(migrate(recorder, version), SCHEMA_VERSION)
                expected = snapshot(db)
                self.assert_integrity(db)
                boundaries = recorder.boundaries
            finally:
                db.close()
            self.assertGreater(len(boundaries), 5)
            self.assertEqual(boundaries[-2:], ["before_commit", "after_commit"])
            for point, label in enumerate(boundaries, 1):
                with self.subTest(version=version, point=point, boundary=label.splitlines()[0]):
                    path = self.home / ("crash-%d-%d.db" % (version, point))
                    shutil.copyfile(template, path)
                    result = subprocess.run(self.command(path, version, point), env=self.environment,
                                            capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, CRASH_EXIT, result.stderr)
                    self.assertEqual(result.stdout, b"")
                    self.assertEqual(result.stderr, b"")
                    recovered = connect(path)
                    try:
                        self.assertEqual(snapshot(recovered), expected if label == "after_commit" else original)
                        self.assert_integrity(recovered)
                        self.assertEqual(migrate(recovered, version), SCHEMA_VERSION)
                        self.assertEqual(snapshot(recovered), expected)
                        self.assert_integrity(recovered)
                    finally:
                        recovered.close()

    def stop_child(self, child):
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)

    def start_child(self, path, version, mode):
        child = subprocess.Popen(self.command(path, version, mode), env=self.environment,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 bufsize=0)
        self.addCleanup(self.stop_child, child)
        return child

    def line(self, child):
        ready, _, _ = select.select([child.stdout], [], [], 10)
        self.assertTrue(ready, "Synthetic migration process did not reach its barrier")
        return child.stdout.readline().strip()

    @unittest.skipUnless(os.name == "posix", "Pipe-barrier test requires the current POSIX runtime")
    def test_stale_opener_rechecks_version_after_competing_migration_commits(self):
        for version in (2, 3, 4):
            with self.subTest(version=version):
                path = self.home / ("competing-%d.db" % version)
                seed(path, version)
                leader = self.start_child(path, version, "leader")
                self.assertEqual(self.line(leader), b"locked")
                follower = self.start_child(path, version, "follower")
                self.assertEqual(self.line(follower), ("observed:%d" % version).encode())
                self.assertEqual(self.line(follower), b"contended")
                self.assertEqual(self.line(follower), b"waiting")
                leader_out, leader_error = leader.communicate(input=b"continue\n", timeout=15)
                follower_out, follower_error = follower.communicate(timeout=15)
                self.assertEqual(leader.returncode, 0, leader_error)
                self.assertEqual(follower.returncode, 0, follower_error)
                self.assertEqual(leader_out, b"complete\n")
                self.assertEqual(follower_out, b"complete\n")
                self.assertEqual(leader_error + follower_error, b"")
                db = connect(path)
                try:
                    self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
                    # v2 cannot run its ALTER TABLE statements twice; this also
                    # verifies the actual backfill survived the waiting opener.
                    expected = 4 if version == 2 else 0
                    self.assertEqual(db.execute("SELECT count(*) FROM audience_sequences").fetchone()[0], expected)
                    self.assert_integrity(db)
                finally:
                    db.close()

    def test_unsupported_versions_are_returned_unchanged_without_ddl(self):
        for version in (0, 1, 999):
            with self.subTest(version=version):
                path = self.home / ("unsupported-%d.db" % version)
                seed(path, 4)
                db = connect(path)
                try:
                    db.execute("PRAGMA user_version=%d" % version)
                    before = snapshot(db)
                    recorded = BoundaryConnection(db)
                    self.assertEqual(migrate(recorded, version), version)
                    self.assertEqual(recorded.boundaries, [])
                    self.assertEqual(snapshot(db), before)
                finally:
                    db.close()


def child_main():
    path, version, point = Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    db = connect(path)
    try:
        if point in ("leader", "follower"):
            observed = db.execute("PRAGMA user_version").fetchone()[0]
            if point == "follower":
                print("observed:%d" % observed, flush=True)
                # Prove real cross-process contention before releasing the
                # leader. The following migration then retries the same stale
                # observed version with the normal bounded busy timeout.
                db.execute("PRAGMA busy_timeout=0")
                try:
                    db.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as error:
                    if "locked" not in str(error):
                        raise
                else:
                    db.rollback()
                    raise RuntimeError("Synthetic leader did not hold the writer lock")
                print("contended", flush=True)
                db.execute("PRAGMA busy_timeout=10000")
            result = migrate(BoundaryConnection(db, mode=point), observed)
            if result != SCHEMA_VERSION:
                raise RuntimeError("Synthetic migration returned an unexpected version")
            print("complete", flush=True)
        else:
            migrate(BoundaryConnection(db, crash_after=int(point)), version)
            raise RuntimeError("Synthetic migration did not reach the requested exit boundary")
    finally:
        db.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--migration-child":
        child_main()
    else:
        unittest.main()
