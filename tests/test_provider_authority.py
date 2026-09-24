"""Provider names are labels, never capability or authorship authority."""

import tempfile
import unittest
from pathlib import Path
from fixtures.harness import private_test_home

from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.projection import Eligibility
from continuum_memory.proposals import proposal_scope
from continuum_memory.security import bounded_provider, digest_json, sign_grant
from continuum_memory.storage import Store, load_capability, paths


class ProviderAuthorityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="continuum-provider-authority-")
        self.addCleanup(self.temp.cleanup)
        self.home = private_test_home(self.temp.name)
        boot = Store.bootstrap(self.home, [
            {"name": name, "path_hint": "/synthetic/" + name,
             "providers": ["codex", "claude", "custom_agent-2"]} for name in ("alpha", "beta")])
        self.projects = {project["name"]: project for project in boot["projects"]}
        self.project = self.projects["alpha"]["id"]
        self.store = Store(self.home)
        self.addCleanup(self.store.close)
        self.kernel = Kernel(self.store, approval_public_key_provider=lambda uid: None,
                             allow_prototype_approval=True)
        self.owner = self.store.authenticate(load_capability(paths(self.home)["control"])["token"])
        self.caps = {name: self.store.authenticate(load_capability(Path(path))["token"])
                     for name, path in self.projects["alpha"]["capabilities"].items()}

    def apply(self, challenge):
        return self.kernel.admin_apply(self.owner, {
            "nonce": challenge["nonce"], "preview_digest": challenge["preview_digest"],
            "preview": challenge["preview"],
            "grant": sign_grant(self.owner["token"].encode("ascii"), challenge["nonce"],
                                challenge["operation"], challenge["preview_digest"]),
        })

    def approve(self, **params):
        params.setdefault("project", self.project)
        return self.apply(self.kernel.admin_preview(self.owner, params))

    def remember(self, **params):
        values = dict(operation="remember", subject="compartment", claim="Synthetic decision.",
                      evidence="Synthetic evidence.", disclosure=["claude"])
        values.update(params)
        return self.approve(**values)

    def proposal(self, provider="codex"):
        return self.kernel.propose(self.caps[provider], {
            "subject": "proposal provenance", "claim": "Synthetic agent claim.",
            "evidence": "Synthetic agent evidence.", "source_handle": "fixture:agent",
            "disclosure": ["codex"], "idempotency_key": "provider-probe-001"})

    def assertDenied(self, callable_, *args):
        with self.assertRaises(MemoryError) as caught:
            callable_(*args)
        self.assertIn(caught.exception.code, {"unauthorized", "forbidden", "invalid_request"})

    def test_reserved_provider_rejected_before_bootstrap_writes(self):
        self.assertDenied(bounded_provider, "user_control")
        target = self.home / "unused-vault"
        self.assertDenied(Store.bootstrap, target, [{"name": "reserved", "path_hint": "/synthetic",
                                                    "providers": ["user_control"]}])
        self.assertFalse(target.exists())
        self.assertEqual(bounded_provider("custom_agent-2"), "custom_agent-2")

    def test_existing_collision_capability_and_direct_calls_fail_closed(self):
        saved = self.remember()
        cap = self.caps["codex"]
        self.store.connection.execute("UPDATE capabilities SET provider='user_control' WHERE id=?", (cap["id"],))
        self.assertDenied(self.store.authenticate, cap["token"])
        collision = dict(cap, provider="user_control")
        before = self.store.connection.total_changes
        for method, params in (("status", {}), ("search", {"query": "compartment"}),
                               ("context", {"query": "compartment"}),
                               ("get", {"recall_id": "rcl_fixture", "ids": [saved["assertion_id"]]}),
                               ("propose", {})):
            with self.subTest(method=method):
                self.assertDenied(getattr(self.kernel, method), collision, params)
        self.assertEqual(self.store.connection.total_changes, before)

    def test_owner_requires_binding_permission_and_principal_together(self):
        for capability in (dict(self.owner, project_id=self.project),
                           dict(self.owner, provider="codex"),
                           dict(self.owner, permissions=["read"]),
                           {key: value for key, value in self.owner.items() if key != "project_id"},
                           dict(self.caps["codex"], permissions=["control", "read"])):
            with self.subTest(capability={key: capability.get(key) for key in ("project_id", "provider", "permissions")}):
                self.assertDenied(self.kernel.status, capability, {})
                self.assertDenied(self.kernel.admin_preview, capability, {})
        self.assertEqual(self.kernel.status(self.owner, {"project": self.project})["recorded_sequence_domain"], "vault_v1")

    def test_plain_provider_label_never_disables_eligibility(self):
        saved = self.remember()
        latest = self.store.connection.execute("SELECT value FROM sequence").fetchone()[0]
        ordinary = Eligibility(self.project, "user_control", latest)
        self.assertEqual(ordinary.rows(self.store.connection), [])
        owner = Eligibility(self.project, "user_control", latest, owner_read=True)
        self.assertEqual([row["id"] for row in owner.rows(self.store.connection)], [saved["assertion_id"]])

    def test_scoped_reads_receipts_watermarks_and_custom_provider(self):
        hidden = self.remember()
        custom = self.caps["custom_agent-2"]
        search = self.kernel.search(custom, {"query": "compartment"})
        self.assertEqual(search["cards"], [])
        self.assertEqual(self.kernel.context(custom, {"query": "compartment"})["accepted_claims"], [])
        with self.assertRaises(MemoryError) as caught:
            self.kernel.get(custom, {"recall_id": search["recall_id"], "ids": [hidden["assertion_id"]]})
        self.assertEqual(caught.exception.code, "not_found")
        before = self.kernel.status(custom, {})
        self.remember(project=self.projects["beta"]["id"], subject="otherproject")
        self.assertEqual(self.kernel.status(custom, {}), before)
        visible = self.remember(subject="custom compartment", disclosure=["custom_agent-2"])
        result = self.kernel.search(custom, {"query": "custom compartment"})
        self.assertEqual([card["version_id"] for card in result["cards"]], [visible["assertion_id"]])
        self.assertEqual(result["recorded_sequence_domain"], "project_provider_v1")
        self.assertEqual(result["projection_watermark"], 1)
        full = self.kernel.get(custom, {"recall_id": result["recall_id"], "ids": [visible["assertion_id"]]})
        self.assertEqual(full["records"][0]["evidence"]["body"], "Synthetic evidence.")
        for method in ("admin_preview", "admin_apply", "admin_result", "audit_reconcile",
                       "approval_info", "audit_verify", "inbox", "show"):
            self.assertDenied(getattr(self.kernel, method), custom, {})

    def test_owner_cross_disclosure_and_history_pagination_remain_available(self):
        saved = [self.remember(subject="compartment %d" % i) for i in range(3)]
        args = {"project": self.project, "query": "compartment", "limit": 1}
        first = self.kernel.search(self.owner, args)
        second = self.kernel.search(self.owner, dict(args, cursor=first["next_cursor"]))
        self.assertNotEqual(first["cards"][0]["version_id"], second["cards"][0]["version_id"])
        self.assertEqual(first["recorded_sequence_domain"], "vault_v1")
        revised = self.approve(operation="correct", target_id=saved[0]["assertion_id"], claim="Revised synthetic.")
        history = self.kernel.show(self.owner, {"project": self.project, "id": saved[0]["memory_id"], "history": True})
        self.assertEqual({row["version_id"] for row in history["versions"]}, {saved[0]["assertion_id"], revised["assertion_id"]})
        owner_context = self.kernel.context(self.owner, {"project": self.project, "query": "compartment"})
        self.assertEqual(len(owner_context["accepted_claims"]), 3)

    def test_unsafe_existing_proposal_cannot_be_accepted_but_can_be_rejected(self):
        proposal = self.proposal()
        challenge = self.kernel.admin_preview(self.owner, {
            "operation": "accept_proposal", "project": self.project, "proposal_id": proposal["proposal_id"]})
        self.store.connection.execute("UPDATE proposals SET source_agent='user_control' WHERE id=?", (proposal["proposal_id"],))
        # Reconstruct an honestly matching, pre-fix preview/challenge over the
        # already-stored collision. A mere post-preview mutation would fail the
        # old state digest too and would not exercise final-apply validation.
        challenge["preview"]["source"]["author"] = "user_control"
        challenge["preview"].update(proposal_scope(self.store, self.project, proposal["proposal_id"]))
        challenge["preview_digest"] = digest_json(challenge["preview"])
        self.store.connection.execute("UPDATE admin_challenges SET preview_digest=? WHERE nonce=?",
                                      (challenge["preview_digest"], challenge["nonce"]))
        before = self.store.connection.total_changes
        self.assertDenied(self.kernel.admin_preview, self.owner, {
            "operation": "accept_proposal", "project": self.project, "proposal_id": proposal["proposal_id"]})
        self.assertEqual(self.store.connection.total_changes, before)
        with self.assertRaises(MemoryError) as caught:
            self.apply(challenge)
        self.assertEqual(caught.exception.code, "invalid_request")
        self.assertEqual(self.store.connection.execute("SELECT status FROM proposals WHERE id=?", (proposal["proposal_id"],)).fetchone()[0], "proposed")
        self.assertIsNone(self.store.connection.execute("SELECT used_at FROM admin_challenges WHERE nonce=?", (challenge["nonce"],)).fetchone()[0])
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM assertion_versions").fetchone()[0], 0)
        self.approve(operation="reject_proposal", proposal_id=proposal["proposal_id"])
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM proposals").fetchone()[0], 0)

    def test_owner_can_forget_unsafe_existing_proposal(self):
        proposal = self.proposal()
        self.store.connection.execute("UPDATE proposals SET source_agent='user_control' WHERE id=?", (proposal["proposal_id"],))
        result = self.approve(operation="forget", target_id=proposal["proposal_id"])
        self.assertEqual(result["completion_state"], "complete")
        self.assertEqual(self.store.connection.execute("SELECT count(*) FROM proposals").fetchone()[0], 0)

    def test_authorship_comes_from_approved_operation_not_provider_label(self):
        proposed = self.proposal()
        accepted = self.approve(operation="accept_proposal", proposal_id=proposed["proposal_id"])
        remembered = self.remember()
        corrected = self.approve(operation="correct", target_id=remembered["assertion_id"], claim="Corrected synthetic.")
        for result, tier, method in ((accepted, "agent_provided", "proposal"),
                                     (remembered, "user_authored", "terminal"),
                                     (corrected, "user_authored", "terminal")):
            evidence = self.store.connection.execute("SELECT e.trust_tier FROM evidence e JOIN assertion_versions a "
                "ON e.id=a.evidence_id WHERE a.id=?", (result["assertion_id"],)).fetchone()[0]
            author = self.store.connection.execute("SELECT method FROM attestations WHERE assertion_id=? AND role='author'",
                                                   (result["assertion_id"],)).fetchone()[0]
            self.assertEqual((evidence, author), (tier, method))

    def test_internal_proposal_writer_cannot_label_agent_evidence_as_terminal(self):
        proposal = self.proposal()
        challenge = self.kernel.admin_preview(self.owner, {
            "operation": "accept_proposal", "project": self.project, "proposal_id": proposal["proposal_id"]})
        # Defense-in-depth unit boundary: even an internal caller supplying a
        # colliding label cannot change the explicit proposal operation's kind.
        # Public acceptance rejects this source before reaching this writer.
        self.store.begin()
        try:
            result = self.kernel._accept_preview(challenge["preview"], "user_control", None, "fixture")
            row = self.store.connection.execute("SELECT e.trust_tier FROM evidence e JOIN assertion_versions a "
                "ON e.id=a.evidence_id WHERE a.id=?", (result["assertion_id"],)).fetchone()
            self.assertEqual(row[0], "agent_provided")
            method = self.store.connection.execute("SELECT method FROM attestations WHERE assertion_id=? AND role='author'",
                                                   (result["assertion_id"],)).fetchone()[0]
            self.assertEqual(method, "proposal")
        finally:
            self.store.rollback()


if __name__ == "__main__":
    unittest.main()
