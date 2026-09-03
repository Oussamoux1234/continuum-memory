import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.security import sign_grant
from continuum_memory.storage import Store, load_capability, paths
from continuum_memory.temporal import canonical_utc


PROJECTS = [
    {"name": "alpha", "path_hint": "/fixture/alpha", "providers": ["codex"]},
]


class MutableClock:
    def __init__(self, value: datetime):
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class DirectKernelHarness:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-retention-")
        self.data_dir = Path(self.temporary.name)
        result = Store.bootstrap(self.data_dir, PROJECTS)
        self.project = result["projects"][0]["id"]
        self.store = Store(self.data_dir)
        self.clock = MutableClock(datetime(2027, 1, 1, tzinfo=timezone.utc))
        self.kernel = Kernel(self.store, now_provider=self.clock)
        self.control = self.store.authenticate(load_capability(paths(self.data_dir)["control"])["token"])
        capability = Path(result["projects"][0]["capabilities"]["codex"])
        self.codex = self.store.authenticate(load_capability(capability)["token"])

    def approve(self, params):
        challenge = self.kernel.admin_preview(self.control, params)
        grant = sign_grant(
            self.control["token"].encode("ascii"),
            challenge["nonce"],
            challenge["operation"],
            challenge["preview_digest"],
        )
        return self.kernel.admin_apply(
            self.control,
            {
                "nonce": challenge["nonce"],
                "preview_digest": challenge["preview_digest"],
                "grant": grant,
                "preview": challenge["preview"],
            },
        )

    def close(self):
        self.store.close()
        self.temporary.cleanup()


class RetentionTest(unittest.TestCase):
    def setUp(self):
        self.harness = DirectKernelHarness()

    def tearDown(self):
        self.harness.close()

    def test_expiry_is_persisted_and_current_recall_stops_resolving(self):
        accepted = self.harness.approve(
            {
                "operation": "remember",
                "project": self.harness.project,
                "subject": "ephemeral setting",
                "claim": "Ephemeral mode is enabled until tomorrow.",
                "retention": "2027-01-02",
                "disclosure": ["codex"],
                "valid_precision": "unknown",
            }
        )
        current = self.harness.kernel.search(
            self.harness.codex, {"query": "Ephemeral", "limit": 5}
        )
        self.assertEqual(current["status"], "ok")

        self.harness.clock.value = datetime(2027, 1, 2, tzinfo=timezone.utc)
        status = self.harness.kernel.status(self.harness.codex, {})
        row = self.harness.store.connection.execute(
            "SELECT lifecycle,retention,retired_seq,retired_at FROM assertion_versions WHERE id=?",
            (accepted["assertion_id"],),
        ).fetchone()
        self.assertEqual(row["lifecycle"], "expired")
        self.assertEqual(row["retention"], "2027-01-02T00:00:00.000000Z")
        self.assertEqual(row["retired_at"], "2027-01-02T00:00:00.000000Z")
        self.assertGreater(row["retired_seq"], accepted["recorded_seq"])
        self.assertEqual(status["projection_watermark"], row["retired_seq"])
        self.assertEqual(
            self.harness.store.connection.execute(
                "SELECT count(*) FROM audit_events WHERE operation='assertion_expired' AND target_id=?",
                (accepted["assertion_id"],),
            ).fetchone()[0],
            1,
        )

        with self.assertRaises(MemoryError) as stale_get:
            self.harness.kernel.get(
                self.harness.codex,
                {"recall_id": current["recall_id"], "ids": [accepted["assertion_id"]]},
            )
        self.assertEqual(stale_get.exception.code, "not_found")
        self.assertEqual(
            self.harness.kernel.search(self.harness.codex, {"query": "Ephemeral"})["status"],
            "no_matches",
        )

        historical = self.harness.kernel.search(
            self.harness.codex, {"query": "Ephemeral", "temporal_mode": "history"}
        )
        self.assertEqual(historical["cards"][0]["lifecycle"], "expired")
        record = self.harness.kernel.get(
            self.harness.codex,
            {"recall_id": historical["recall_id"], "ids": [accepted["assertion_id"]]},
        )["records"][0]
        self.assertEqual(record["lifecycle"], "expired")
        self.assertEqual(self.harness.store.verify_audit()["status"], "valid")

    def test_expired_retention_is_rejected_at_preview_and_apply(self):
        with self.assertRaises(MemoryError) as past:
            self.harness.kernel.admin_preview(
                self.harness.control,
                {
                    "operation": "remember",
                    "project": self.harness.project,
                    "subject": "past retention",
                    "claim": "This must not be admitted.",
                    "retention": "2026-12-31T23:59:59Z",
                },
            )
        self.assertEqual(past.exception.code, "invalid_request")

        proposed = self.harness.kernel.propose(
            self.harness.codex,
            {
                "subject": "deadline race",
                "claim": "A proposal cannot outlive its retention deadline.",
                "evidence": "Synthetic evidence",
                "source_handle": "fixture:deadline",
                "retention": "2027-01-02T00:00:00Z",
                "disclosure": ["codex"],
                "idempotency_key": "deadline-race-0001",
            },
        )
        challenge = self.harness.kernel.admin_preview(
            self.harness.control,
            {
                "operation": "accept_proposal",
                "project": self.harness.project,
                "proposal_id": proposed["proposal_id"],
            },
        )
        grant = sign_grant(
            self.harness.control["token"].encode("ascii"),
            challenge["nonce"],
            challenge["operation"],
            challenge["preview_digest"],
        )
        self.harness.clock.value = datetime(2027, 1, 2, tzinfo=timezone.utc)
        with self.assertRaises(MemoryError) as expired:
            self.harness.kernel.admin_apply(
                self.harness.control,
                {
                    "nonce": challenge["nonce"],
                    "preview_digest": challenge["preview_digest"],
                    "grant": grant,
                    "preview": challenge["preview"],
                },
            )
        self.assertEqual(expired.exception.code, "retention_expired")
        self.assertEqual(
            self.harness.store.connection.execute(
                "SELECT count(*) FROM assertion_versions WHERE project_id=?",
                (self.harness.project,),
            ).fetchone()[0],
            0,
        )

    def test_strict_dates_reject_invalid_values_and_normalize_offsets(self):
        invalid_values = [
            "2025-02-29",
            "2024-13-01",
            "2027-01-02T03:04:05",
            "2027-01-02 03:04:05Z",
            "2027-01-02T24:00:00Z",
            "2027-01-02T03:04:05+14:01",
            "2027-01-02T03:04:05-00:00",
            "2027-01-02T03:04:05Zextra",
        ]
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(MemoryError):
                canonical_utc(value, "timestamp")
        self.assertEqual(canonical_utc("2024-02-29", "timestamp"), "2024-02-29T00:00:00.000000Z")
        self.assertEqual(
            canonical_utc("2027-01-02T03:04:05.12+02:30", "timestamp"),
            "2027-01-02T00:34:05.120000Z",
        )
        precision, start, end = self.harness.kernel._valid_time(
            {
                "valid_precision": "interval",
                "valid_from": "2027-01-01T03:00:00+03:00",
                "valid_to": "2027-01-02",
            }
        )
        self.assertEqual(precision, "interval")
        self.assertEqual(start, "2027-01-01T00:00:00.000000Z")
        self.assertEqual(end, "2027-01-02T00:00:00.000000Z")


if __name__ == "__main__":
    unittest.main()
