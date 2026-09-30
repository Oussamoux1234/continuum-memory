"""Pure audit-algorithm regressions, not encrypted-storage acceptance evidence."""

import sqlite3
import unittest

from continuum_memory.audit_validation import verify_audit_snapshot
from continuum_memory.errors import MemoryError
from continuum_memory.migrations import SCHEMA_SQL
from continuum_memory.storage import Store


class AuditSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(self.connection.close)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA_SQL)
        self.key = b"a" * 32
        self.heads = [{"audit_seq": 0, "mac": "GENESIS"}]
        for seq in (1, 2, 3):
            Store._append_audit_raw(self.connection, self.key, seq, "user_control", "synthetic",
                                    "scope_fixture", "target_fixture", "allowed", "ok", "2026-09-23")
            row = self.connection.execute("SELECT audit_seq,mac FROM audit_events ORDER BY audit_seq DESC").fetchone()
            self.heads.append(dict(row))

    def verify(self, anchor=None):
        return verify_audit_snapshot(self.connection, self.key, lambda: self.heads[-1] if anchor is None else anchor)

    def test_valid_head_and_empty_genesis(self):
        self.assertEqual(self.verify(), {"status": "valid", "events": 3, "head": self.heads[-1]["mac"]})
        self.connection.execute("DELETE FROM audit_events")
        self.assertEqual(self.verify(self.heads[0]), {"status": "valid", "events": 0, "head": "GENESIS"})

    def test_exact_old_prefix_is_stale_not_repaired(self):
        for head in self.heads[:-1]:
            self.assertEqual(self.verify(head), {"status": "external_anchor_stale", "events": 3,
                                                "anchor_audit_seq": head["audit_seq"]})

    def test_ahead_anchor_detects_tail_rollback(self):
        self.assertEqual(self.verify({"audit_seq": 4, "mac": "0" * 64}),
                         {"status": "database_tail_rollback", "events": 3, "anchor_audit_seq": 4})

    def test_wrong_prefix_and_current_mac_never_qualify_for_reconciliation(self):
        for seq in (1, 3):
            self.assertEqual(self.verify({"audit_seq": seq, "mac": "0" * 64}),
                             {"status": "anchor_mismatch", "events": 3})

    def test_malformed_anchor_shapes_and_types(self):
        malformed = [[], {}, {"audit_seq": True, "mac": "GENESIS"}, {"audit_seq": -1, "mac": "GENESIS"},
                     {"audit_seq": 0, "mac": "0" * 64}, {"audit_seq": 1, "mac": "bad"},
                     {"audit_seq": 1, "mac": "A" * 64}, {"audit_seq": 1, "mac": None},
                     {"audit_seq": 1, "mac": "0" * 64, "extra": "untrusted"}]
        for anchor in malformed:
            with self.subTest(anchor=anchor):
                self.assertEqual(self.verify(anchor), {"status": "anchor_malformed", "events": 3})

    def test_missing_invalid_or_unsafe_anchor_errors_remain_content_free(self):
        for error in (OSError("sensitive-path"), ValueError("sensitive-parser-input"), RecursionError(),
                      MemoryError("unsafe_file", "sensitive-path")):
            def unavailable():
                raise error
            self.assertEqual(verify_audit_snapshot(self.connection, self.key, unavailable),
                             {"status": "anchor_unavailable", "events": 3})

    def test_internal_link_failure_precedes_anchor_loading(self):
        self.connection.execute("UPDATE audit_events SET previous_mac='broken' WHERE audit_seq=2")
        self.assertEqual(self.verify(), {"status": "invalid_internal_link", "first_invalid_audit_seq": 2})

    def test_modified_payload_or_wrong_key_rejects_event_mac(self):
        self.assertEqual(verify_audit_snapshot(self.connection, b"b" * 32, lambda: self.heads[-1]),
                         {"status": "invalid_event_mac", "first_invalid_audit_seq": 1})
        self.connection.execute("UPDATE audit_events SET operation='altered' WHERE audit_seq=2")
        self.assertEqual(self.verify(), {"status": "invalid_event_mac", "first_invalid_audit_seq": 2})

    def test_helper_never_writes_or_owns_the_callers_transaction(self):
        self.connection.execute("BEGIN IMMEDIATE")
        before = self.connection.total_changes
        self.verify()
        self.assertTrue(self.connection.in_transaction)
        self.assertEqual(self.connection.total_changes, before)
        self.connection.rollback()


if __name__ == "__main__":
    unittest.main()
