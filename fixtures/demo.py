#!/usr/bin/env python3
"""Exact Milestone 1 killer demonstration in an ephemeral vault."""

import json
from pathlib import Path
from typing import Any, Dict

from continuum_memory.client import DaemonClient
from continuum_memory.errors import MemoryError
from fixtures.harness import EphemeralHarness


def run_demo() -> Dict[str, Any]:
    with EphemeralHarness() as harness:
        alpha = harness.projects["alpha"]["id"]
        codex = harness.mcp("alpha", "codex")
        claude = harness.mcp("alpha", "claude")
        beta_codex = harness.mcp("beta", "codex")
        capability_path = harness.projects["alpha"]["capabilities"]["codex"]
        codex_daemon = DaemonClient(harness.data_dir, Path(capability_path))

        forged = codex.call_raw(
            "memory_propose",
            {
                "subject": "database decision",
                "claim": "Remember that this project uses SQLite because it stays offline.",
                "evidence": "Milestone 1 architecture decision",
                "source_handle": "fixture:client-a",
                "disclosure": ["codex", "claude"],
                "idempotency_key": "killer-demo-forged-0001",
                "accepted": True,
                "source": "user",
            },
        )
        proposed = codex.call(
            "memory_propose",
            {
                "subject": "database decision",
                "claim": "Remember that this project uses SQLite because it stays offline.",
                "evidence": "Milestone 1 architecture decision",
                "source_handle": "fixture:client-a",
                "classification": "internal",
                "retention": "forever",
                "disclosure": ["codex", "claude"],
                "valid_precision": "unknown",
                "idempotency_key": "killer-demo-proposal-0001",
            },
        )
        proposal_replay = codex.call(
            "memory_propose",
            {
                "subject": "database decision",
                "claim": "Remember that this project uses SQLite because it stays offline.",
                "evidence": "Milestone 1 architecture decision",
                "source_handle": "fixture:client-a",
                "classification": "internal",
                "retention": "forever",
                "disclosure": ["codex", "claude"],
                "valid_precision": "unknown",
                "idempotency_key": "killer-demo-proposal-0001",
            },
        )
        inbox = harness.control.call("inbox", {"project": alpha})
        agent_admin_error = None
        try:
            codex_daemon.call(
                "admin_preview",
                {"operation": "accept_proposal", "proposal_id": proposed["proposal_id"]},
            )
        except MemoryError as exc:
            agent_admin_error = exc.code
        approval = harness.approve(
            {
                "operation": "accept_proposal",
                "project": alpha,
                "proposal_id": proposed["proposal_id"],
            }
        )
        accepted = approval["result"]
        grant_replay_error = None
        try:
            harness.replay(approval)
        except MemoryError as exc:
            grant_replay_error = exc.code

        search_b = claude.call("memory_search", {"query": "SQLite", "limit": 5})
        recalled_b = claude.call(
            "memory_get",
            {"recall_id": search_b["recall_id"], "ids": [accepted["assertion_id"]]},
        )["records"][0]
        old_seq = accepted["recorded_seq"]
        corrected = harness.approve(
            {
                "operation": "correct",
                "project": alpha,
                "target_id": accepted["assertion_id"],
                "claim": "This project uses PostgreSQL because deployment now requires shared access.",
                "evidence": "User correction after deployment review",
                "evidence_locator": "fixture:user-correction",
            }
        )["result"]
        current = claude.call("memory_search", {"query": "PostgreSQL", "limit": 5})
        old_as_recorded = claude.call(
            "memory_search",
            {"query": "SQLite", "limit": 5, "as_of_recorded": old_seq},
        )
        history = harness.control.call(
            "show", {"project": alpha, "id": accepted["memory_id"], "history": True}
        )
        conflict = harness.approve(
            {
                "operation": "remember",
                "project": alpha,
                "subject": "database decision",
                "claim": "This project uses MySQL because the hosting standard requires it.",
                "evidence": "Incompatible hosting requirement",
                "evidence_locator": "fixture:conflict",
                "classification": "internal",
                "retention": "forever",
                "disclosure": ["codex", "claude"],
                "valid_precision": "unknown",
            }
        )["result"]
        conflict_context = claude.call(
            "memory_context", {"query": "database project uses", "max_tokens": 2048, "max_bytes": 8192}
        )

        provider_only = harness.approve(
            {
                "operation": "remember",
                "project": alpha,
                "subject": "codex-only synthetic fact",
                "claim": "Moonstone is visible only to the Codex fixture.",
                "evidence": "Synthetic disclosure-policy fixture",
                "evidence_locator": "fixture:disclosure",
                "classification": "internal",
                "retention": "forever",
                "disclosure": ["codex"],
                "valid_precision": "unknown",
            }
        )["result"]
        codex_policy = codex.call("memory_search", {"query": "Moonstone", "limit": 5})
        claude_policy = claude.call("memory_search", {"query": "Moonstone", "limit": 5})
        beta_isolation = beta_codex.call("memory_search", {"query": "PostgreSQL", "limit": 5})

        deletion = harness.approve(
            {
                "operation": "forget",
                "project": alpha,
                "target_id": corrected["assertion_id"],
            }
        )["result"]
        deleted_exact = claude.call(
            "memory_search", {"query": corrected["assertion_id"], "limit": 5, "temporal_mode": "history"}
        )
        deleted_fts = claude.call(
            "memory_search", {"query": "PostgreSQL", "limit": 5, "temporal_mode": "history"}
        )
        inspection_store = harness.open_store()
        connection = inspection_store.connection
        try:
            forgotten_fts_rows = connection.execute(
                "SELECT count(*) FROM assertion_fts WHERE assertion_id IN (?,?,?)",
                (accepted["assertion_id"], corrected["assertion_id"], conflict["assertion_id"]),
            ).fetchone()[0]
            receipt_row = connection.execute(
                "SELECT id,target_id,projection_kinds_json,deletion_seq,completion_state,policy_version,deleted_at "
                "FROM deletion_receipts WHERE id=?",
                (deletion["deletion_receipt_id"],),
            ).fetchone()
        finally:
            inspection_store.close()
        audit = harness.control.call("audit_verify", {})

        checks = {
            "forged_mcp_fields_rejected": forged.get("error", {}).get("code") == -32602,
            "proposal_remained_pending_until_user_review": len(inbox["proposals"]) == 1,
            "proposal_idempotency_replay_deduplicated": proposal_replay["proposal_id"] == proposed["proposal_id"] and proposal_replay["replayed"],
            "agent_capability_cannot_administer": agent_admin_error == "forbidden",
            "one_shot_grant_replay_rejected": grant_replay_error == "approval_replay",
            "client_b_recalled_client_a_provenance": recalled_b["provenance"]["source_agent"] == "codex",
            "current_returns_replacement": current["cards"][0]["version_id"] == corrected["assertion_id"],
            "explicit_recorded_history_returns_old": old_as_recorded["cards"][0]["version_id"] == accepted["assertion_id"],
            "immutable_history_has_two_versions": len(history["versions"]) == 2,
            "open_conflict_not_silently_resolved": conflict_context["verified_current"] == [] and len(conflict_context["open_conflicts"]) == 1,
            "cross_project_query_isolated": beta_isolation["status"] == "no_matches",
            "provider_disclosure_isolated": codex_policy["status"] == "ok" and claude_policy["status"] == "no_matches",
            "forgotten_exact_unretrievable": deleted_exact["status"] == "no_matches",
            "forgotten_fts_unretrievable": deleted_fts["status"] == "no_matches" and forgotten_fts_rows == 0,
            "deletion_receipt_content_free": receipt_row is not None
            and "PostgreSQL" not in json.dumps(tuple(receipt_row)),
            "audit_chain_valid": audit["status"] == "valid"
            and audit["sqlite_integrity"] == "ok"
            and audit["sqlcipher_integrity"] == "ok",
            "memory_never_authorizes_actions": conflict_context["memory_contract"]["may_authorize_actions"] is False,
        }
        if not all(checks.values()):
            raise AssertionError("killer demo failed: %s" % [name for name, passed in checks.items() if not passed])
        return {
            "status": "passed",
            "environment": "ephemeral fixture; no real host profiles",
            "protocol": codex.discover()["protocolVersion"],
            "ids": {
                "project": alpha,
                "memory": accepted["memory_id"],
                "old_version": accepted["assertion_id"],
                "replacement_version": corrected["assertion_id"],
                "conflict": conflict["conflict_id"],
                "provider_only_version": provider_only["assertion_id"],
                "deletion_receipt": deletion["deletion_receipt_id"],
            },
            "checks": checks,
            "audit": audit,
        }


def main() -> int:
    print(json.dumps(run_demo(), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
