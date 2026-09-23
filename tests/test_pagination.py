"""Bounded live-revalidated pagination over synthetic, disposable vaults."""

import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from continuum_memory.cli import build_parser
from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.pagination import Cursors
from continuum_memory.security import MAX_FRAME_BYTES, canonical_json
from continuum_memory.storage import load_capability
from continuum_memory.transport import encode_frame
from tests import test_snapshot_forget as fixture


class PaginationTest(unittest.TestCase):
    setUp = fixture.SnapshotForgetTest.setUp
    tearDown = fixture.SnapshotForgetTest.tearDown
    apply = fixture.SnapshotForgetTest.apply
    approve = fixture.SnapshotForgetTest.approve
    remember = fixture.SnapshotForgetTest.remember
    context = fixture.SnapshotForgetTest.context

    def search(self, **options):
        return self.kernel.search(self.codex, dict(query="engine", **options))

    def ids(self, response):
        return [card["version_id"] for card in response["cards"]]

    def test_search_traverses_over_26_in_stable_order_without_gaps_or_duplicates(self):
        saved = [self.remember(subject="engine %d" % i) for i in range(31)]
        expected = [item["assertion_id"] for item in reversed(saved)]
        seen, options, watermarks = [], {"limit": 25}, set()
        for _ in range(32):
            page = self.search(**options)
            seen.extend(self.ids(page))
            watermarks.add(page["projection_watermark"])
            self.assertLessEqual(len(page["cards"]), 25)
            if "next_cursor" not in page:
                self.assertEqual(page["completeness"], "complete")
                break
            self.assertEqual(page["completeness"], "partial")
            options["cursor"] = page["next_cursor"]
        self.assertEqual(seen, expected)
        self.assertEqual(len(watermarks), 1)

    def test_history_beyond_five_keeps_snapshot_and_keyset(self):
        first = self.remember()
        versions = [first["assertion_id"]]
        for i in range(8):
            revised = self.approve(operation="correct", target_id=versions[-1], claim="Engine revision %d." % i)
            versions.append(revised["assertion_id"])
        args = {"project": self.project, "id": first["memory_id"], "history": True}
        one = self.kernel.show(self.control, args)
        self.assertEqual([r["version_id"] for r in one["versions"]], versions[:5])
        self.approve(operation="correct", target_id=versions[-1], claim="Engine later revision.")
        two = self.kernel.show(self.control, dict(args, cursor=one["next_cursor"]))
        self.assertEqual([r["version_id"] for r in two["versions"]], versions[5:])
        self.assertEqual(two["total_versions"], 9)
        self.assertEqual(two["completeness"], "complete")
        self.assertEqual(two["versions"][-1]["lifecycle"], "active")

    def test_search_rechecks_forget_and_disclosure_but_pins_new_writes_and_corrections(self):
        saved = [self.remember(subject="engine %d" % i) for i in range(7)]
        one = self.search(limit=2)
        self.approve(operation="forget", target_id=saved[3]["assertion_id"])
        self.approve(operation="correct", target_id=saved[4]["assertion_id"], claim="Engine correction.")
        later = self.remember(subject="engine later")
        # Synthetic future disclosure mutation: reads must consult the live table.
        self.store.connection.execute("DELETE FROM assertion_disclosures WHERE assertion_id=?", (saved[2]["assertion_id"],))
        two = self.search(limit=25, cursor=one["next_cursor"])
        self.assertEqual(self.ids(two), [saved[i]["assertion_id"] for i in (4, 1, 0)])
        self.assertNotIn(later["assertion_id"], canonical_json(two))
        self.assertNotIn(saved[3]["assertion_id"], canonical_json(two))
        self.assertEqual(two["cards"][0]["lifecycle"], "active")
        replay = self.search(limit=25, cursor=one["next_cursor"])
        self.assertEqual(self.ids(replay), self.ids(two))
        # Forget after a replay revokes the same token too.
        self.approve(operation="forget", target_id=saved[4]["assertion_id"])
        self.assertEqual(self.ids(self.search(limit=25, cursor=one["next_cursor"])),
                         [saved[i]["assertion_id"] for i in (1, 0)])

    def test_expiry_after_first_page_is_recorded_history_not_snapshot_rewrite(self):
        old = self.remember(subject="engine expiring", retention="2027-01-02")
        self.remember(subject="engine newest")
        one = self.search(limit=1)
        self.now = datetime(2027, 1, 3, tzinfo=timezone.utc)
        page = self.search(cursor=one["next_cursor"])
        self.assertEqual(self.ids(page), [old["assertion_id"]])
        self.assertEqual(page["cards"][0]["lifecycle"], "active")
        self.assertNotIn(old["assertion_id"], self.ids(self.search()))

    def test_first_page_receipt_pins_correction_and_expiry_but_not_forget(self):
        for operation in ("search", "context"):
            with self.subTest(operation=operation):
                saved = [self.remember(subject="receipt %s %d" % (operation, i),
                                       retention="2027-01-02") for i in range(4)]
                args = {"query": "receipt " + operation}
                args.update({"limit": 1} if operation == "search" else {"max_tokens": 512})
                first = getattr(self.kernel, operation)(self.codex, args)
                self.assertIn("next_cursor", first)
                card = (first["cards"] if operation == "search" else first["accepted_claims"])[0]
                target = card["version_id"]
                self.approve(operation="correct", target_id=target, claim="Corrected receipt.")
                self.now = datetime(2027, 1, 3, tzinfo=timezone.utc)
                get_args = {"recall_id": first["recall_id"], "ids": [target]}
                full = self.kernel.get(self.codex, get_args)["records"][0]
                self.assertEqual(full["lifecycle"], "active")
                self.assertEqual(full["version_id"], target)
                self.approve(operation="forget", target_id=target)
                with self.assertRaises(MemoryError) as caught:
                    self.kernel.get(self.codex, get_args)
                self.assertEqual(caught.exception.code, "not_found")
                self.now = datetime(2027, 1, 1, tzinfo=timezone.utc)

    def test_hidden_and_visible_corpus_mutations_cannot_change_keyset_relevance(self):
        saved = [self.remember(subject="engine %d" % i,
                               claim="engine " * (i % 3 + 1), disclosure=["codex"]) for i in range(29)]
        expected = [saved[i]["assertion_id"] for i in sorted(range(29), key=lambda i: (-(i % 3 + 1), -i))]
        first = self.search(limit=3)
        for i in range(35):
            self.remember(subject="engine corpus %d" % i, claim="engine " * 20,
                          project=self.projects["beta"]["id"] if i % 2 else self.project,
                          disclosure=["claude"] if i % 2 == 0 else ["*"])
        for i in range(5):
            self.remember(subject="engine new visible %d" % i, claim="engine " * 20)
        seen = self.ids(first)
        cursor = first["next_cursor"]
        for _ in range(30):
            page = self.search(limit=3, cursor=cursor)
            seen.extend(self.ids(page))
            if "next_cursor" not in page:
                break
            cursor = page["next_cursor"]
        self.assertEqual(seen, expected)

    def test_exact_thread_continuation_cannot_fall_back_to_fts_after_forget(self):
        first = self.remember()
        for i in range(3):
            self.remember(claim="Engine choice %d." % i)
        self.remember(subject="unrelated", claim="Contains identifier " + first["memory_id"])
        page = self.kernel.search(self.codex, {"query": first["memory_id"], "limit": 1})
        self.approve(operation="forget", target_id=first["memory_id"])
        result = self.kernel.search(self.codex, {"query": first["memory_id"], "cursor": page["next_cursor"]})
        self.assertEqual(result["cards"], [])
        self.assertEqual(result["completeness"], "complete")

    def test_tokens_reject_project_provider_capability_query_and_temporal_reuse_uniformly(self):
        for i in range(3):
            self.remember(subject="engine %d" % i, valid_precision="open", valid_from="2026-01-01")
        args = {"query": "engine", "limit": 1, "as_of_valid": "2027-01-01"}
        token = self.kernel.search(self.codex, args)["next_cursor"]
        other_provider = self.store.authenticate(load_capability(Path(self.projects["alpha"]["capabilities"]["claude"]))["token"])
        other_project = self.store.authenticate(load_capability(Path(self.projects["beta"]["capabilities"]["codex"]))["token"])
        altered_capability = dict(self.codex, id="cap_other")
        cases = [(other_provider, {}), (other_project, {}), (altered_capability, {}),
                 (self.codex, {"query": "hidden-query-canary"}), (self.codex, {"temporal_mode": "history"}),
                 (self.codex, {"as_of_recorded": 1}), (self.codex, {"as_of_valid": "2028-01-01"}),
                 (self.codex, {"cursor": token + "x"}), (self.codex, {"cursor": []}),
                 (self.codex, {"cursor": "x" * 65536})]
        errors = []
        for capability, changes in cases:
            with self.assertRaises(MemoryError) as caught:
                self.kernel.search(capability, dict(args, cursor=token, **changes) if "cursor" not in changes
                                   else dict(args, **changes))
            errors.append(caught.exception.as_dict())
        self.assertTrue(all(error == errors[0] for error in errors))
        self.assertEqual(errors[0]["code"], "invalid_cursor")
        with self.assertRaises(MemoryError) as caught:
            self.kernel.context(self.codex, {"query": "engine", "as_of_valid": "2027-01-01", "cursor": token})
        self.assertEqual(caught.exception.code, "invalid_cursor")

    def test_cursor_ttl_capacity_restart_and_content_free_bounded_state(self):
        cache = Cursors()
        with patch("continuum_memory.pagination.time.monotonic", return_value=0):
            oldest = cache.issue("binding", 1, (1, 1, "ast_synthetic"))
            for _ in range(256):
                newest = cache.issue("binding", 1, (1, 1, "ast_synthetic"))
            self.assertEqual(len(cache.entries), 256)
            for token, tested in ((oldest, cache), (newest, Cursors())):
                with self.assertRaises(MemoryError):
                    tested.read(token, "binding")
            self.assertEqual(cache.read(newest, "binding")["recorded"], 1)
        with patch("continuum_memory.pagination.time.monotonic", return_value=600):
            with self.assertRaises(MemoryError):
                cache.read(newest, "binding")
            self.assertEqual(len(cache.entries), 0)
        for i in range(2):
            self.remember(subject="engine %d" % i)
        result = self.search(limit=1)
        self.assertNotIn("Engine uses SQLite", canonical_json(list(self.kernel._cursors.entries.values())))
        self.assertNotIn("engine", canonical_json(list(self.kernel._cursors.entries.values())))
        restarted = Kernel(self.store)
        with self.assertRaises(MemoryError):
            restarted.search(self.codex, {"query": "engine", "cursor": result["next_cursor"]})

    def test_context_byte_packing_advances_only_emitted_candidates(self):
        saved = [self.remember(subject="engine %d" % i) for i in range(29)]
        seen, args = [], {"query": "engine", "max_bytes": 3500, "max_tokens": 2048}
        for _ in range(30):
            page = self.kernel.context(self.codex, args)
            self.assertLessEqual(len(canonical_json(page).encode("utf-8")), 3500)
            seen.extend(c["version_id"] for c in page["accepted_claims"])
            if "next_cursor" not in page:
                break
            self.assertTrue(page["accepted_claims"])
            args["cursor"] = page["next_cursor"]
        self.assertEqual(seen, [r["assertion_id"] for r in reversed(saved)])
        with self.assertRaises(MemoryError) as caught:
            self.kernel.context(self.codex, {"query": "engine", "max_tokens": 128})
        self.assertEqual(caught.exception.code, "budget_too_small")

    def test_giant_conflict_is_bounded_not_a_winner_and_members_are_traversable(self):
        saved = [self.remember(claim="Engine choice %d." % i) for i in range(28)]
        args = {"query": saved[0]["memory_id"], "max_tokens": 2048}
        seen = []
        for _ in range(29):
            page = self.kernel.context(self.codex, args)
            self.assertEqual(page["accepted_claims"], [])
            self.assertEqual(page["completeness"], "partial")
            self.assertLessEqual(len(canonical_json(page).encode("utf-8")), 8192)
            self.assertEqual(len(page["open_conflicts"]), 1)
            group = page["open_conflicts"][0]
            self.assertEqual(group["status"], "not_fully_assessed")
            self.assertEqual(group["membership_completeness"], "partial")
            self.assertTrue(all(c["conflict_assessment"] == "not_fully_assessed" for c in group["members"]))
            seen.extend(c["version_id"] for c in group["members"])
            if "next_cursor" not in page:
                break
            args["cursor"] = page["next_cursor"]
        self.assertEqual(seen, [r["assertion_id"] for r in reversed(saved)])
        history = self.kernel.show(self.control, {"project": self.project, "id": saved[0]["memory_id"], "history": True})
        self.assertIn("next_cursor", history)

    def test_partial_small_conflict_is_explicit_even_with_only_one_matching_member(self):
        first = self.remember(subject="database", claim="Apple is selected.")
        self.remember(subject="database", claim="Banana is selected.")
        result = self.context("Apple")
        self.assertEqual(result["accepted_claims"], [])
        self.assertEqual(result["completeness"], "partial")
        self.assertEqual(result["open_conflicts"][0]["membership_completeness"], "partial")
        self.assertEqual([c["version_id"] for c in result["open_conflicts"][0]["members"]], [first["assertion_id"]])

    def test_large_encoded_cards_and_owner_history_fit_transport_frames(self):
        for i in range(10):
            self.remember(subject="engine %d" % i, claim="engine " + "\t" * 3000)
        response = self.search(limit=25)
        self.assertIn("next_cursor", response)
        wire = {"jsonrpc": "2.0", "id": "test", "result": {
            "content": [{"type": "text", "text": canonical_json(response)}], "structuredContent": response}}
        self.assertLess(len(encode_frame(wire)), MAX_FRAME_BYTES)
        for i in range(6):
            large = self.remember(subject="large evidence", claim="engine %d " % i + "\t" * 3000)
        shown = self.kernel.show(self.control, {"project": self.project, "id": large["memory_id"], "history": True})
        self.assertLess(len(encode_frame({"result": shown})), MAX_FRAME_BYTES)

    def test_cli_cursor_plumbing(self):
        parser = build_parser()
        for command, extra in (("search", ["--query", "engine"]), ("context", ["--query", "engine"]),
                               ("show", ["mem_synthetic", "--history"])):
            parsed = parser.parse_args([command, "--project", self.project, "--cursor", "cur_synthetic"] + extra)
            self.assertEqual(parsed.cursor, "cur_synthetic")


if __name__ == "__main__":
    unittest.main()
