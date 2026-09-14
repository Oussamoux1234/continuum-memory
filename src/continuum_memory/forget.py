"""Exact deletion scope and dependent-state preconditions for owner approval."""
import json

from .errors import MemoryError, NOT_FOUND
from .security import canonical_json


def forget_scope(store, project, thread_id):
    db = store.connection
    thread = db.execute("SELECT * FROM claim_threads WHERE id=? AND project_id=?",
                        (thread_id, project)).fetchone()
    if thread is None:
        raise NOT_FOUND
    versions = "SELECT id FROM assertion_versions WHERE thread_id=?"
    evidence = ("SELECT evidence_id FROM evidence_refs WHERE assertion_id IN (" + versions + ")")
    proposals = "SELECT id FROM proposals WHERE project_id=? AND subject_key=?"
    conflicts = "SELECT id FROM conflicts WHERE thread_id=?"
    state = {}
    identifiers = {}

    def collect(name, table, predicate, args, keys=("id",)):
        select = "rowid AS fts_rowid,*" if table == "assertion_fts" else "*"
        rows = [dict(row) for row in db.execute("SELECT " + select + " FROM " + table + " WHERE " + predicate, args)]
        state[name] = sorted(rows, key=canonical_json)
        identifiers[name] = sorted([{key: row[key] for key in keys} for row in rows], key=canonical_json)

    collect("threads", "claim_threads", "id=? AND project_id=?", (thread_id, project))
    collect("versions", "assertion_versions", "thread_id=?", (thread_id,))
    for table in ("attestations", "consent_receipts", "feedback"):
        collect(table, table, "assertion_id IN (" + versions + ")", (thread_id,))
    collect("disclosures", "assertion_disclosures", "assertion_id IN (" + versions + ")",
            (thread_id,), ("assertion_id", "provider"))
    collect("evidence_refs", "evidence_refs", "assertion_id IN (" + versions + ")",
            (thread_id,), ("evidence_id", "assertion_id"))
    # Shared references are preconditions: their addition changes whether an
    # evidence body will be deleted, even when no version is added to this thread.
    collect("shared_evidence_refs_precondition", "evidence_refs",
            "evidence_id IN (" + evidence + ") AND assertion_id NOT IN (" + versions + ")",
            (thread_id, thread_id), ("evidence_id", "assertion_id"))
    shared = ("EXISTS (SELECT 1 FROM evidence_refs er WHERE er.evidence_id=evidence.id "
              "AND er.assertion_id NOT IN (" + versions + "))")
    collect("owned_evidence", "evidence", "id IN (" + evidence + ") AND NOT " + shared,
            (thread_id, thread_id))
    collect("retained_evidence_precondition", "evidence", "id IN (" + evidence + ") AND " + shared,
            (thread_id, thread_id))
    collect("proposals", "proposals", "project_id=? AND subject_key=?", (project, thread["subject_key"]))
    collect("reviews", "reviews", "proposal_id IN (" + proposals + ")", (project, thread["subject_key"]))
    collect("provenance_activities", "provenance_activities", "project_id=? AND (target_id IN (" + versions
            + ") OR target_id IN (" + proposals + "))", (project, thread_id, project, thread["subject_key"]))
    collect("relations", "relations", "from_assertion_id IN (" + versions + ") OR to_assertion_id IN (" + versions + ")",
            (thread_id, thread_id))
    collect("conflicts", "conflicts", "thread_id=?", (thread_id,))
    collect("conflict_members", "conflict_members", "conflict_id IN (" + conflicts + ") OR assertion_id IN (" + versions + ")",
            (thread_id, thread_id), ("conflict_id", "assertion_id"))
    collect("fts", "assertion_fts", "assertion_id IN (" + versions + ")", (thread_id,), ("fts_rowid", "assertion_id"))
    assertion_ids = {row["id"] for row in state["versions"]}
    recalls = []
    for row in db.execute("SELECT * FROM recalls WHERE project_id=? ORDER BY id", (project,)):
        try:
            result_ids = json.loads(row["result_ids_json"])
        except (TypeError, ValueError) as exc:
            raise MemoryError("integrity_error", "A recall result index is malformed.") from exc
        if not isinstance(result_ids, list) or any(not isinstance(item, str) for item in result_ids):
            raise MemoryError("integrity_error", "A recall result index is malformed.")
        if assertion_ids.intersection(result_ids):
            recalls.append(dict(row))
    state["recalls_to_prune"] = recalls
    identifiers["recalls_to_prune"] = [
        {"id": row["id"], "remove_ids": sorted(assertion_ids.intersection(json.loads(row["result_ids_json"])))}
        for row in recalls
    ]
    return {
        "affected_set": identifiers,
        "state_digest": store.keyed_digest("forget-scope-v1", canonical_json(state)),
    }
