"""Proposal deletion scopes and content-free delivery suppression."""
from .errors import MemoryError, NOT_FOUND
from .security import canonical_json


def delivery_digest(store, project, provider, delivery_key):
    # Caller-controlled keys can themselves contain content. Never retain a raw
    # delivery key in the tombstone, nor a digest of the proposal body/evidence.
    return store.keyed_digest("proposal-delivery-v1", canonical_json([project, provider, delivery_key]))


def check_delivery(store, project, provider, key_digest):
    if store.connection.execute(
        "SELECT 1 FROM proposal_tombstones WHERE project_id=? AND provider=? AND delivery_digest=?",
        (project, provider, key_digest),
    ).fetchone():
        raise MemoryError("delivery_suppressed", "This delivery was purged and cannot be replayed.")


def proposal_scope(store, project, proposal_id):
    db = store.connection
    row = db.execute("SELECT * FROM proposals WHERE project_id=? AND id=?", (project, proposal_id)).fetchone()
    if row is None:
        raise NOT_FOUND
    state = {"proposals": [dict(row)]}
    state["reviews"] = [dict(item) for item in db.execute(
        "SELECT * FROM reviews WHERE proposal_id=? ORDER BY id", (proposal_id,))]
    state["provenance_activities"] = [dict(item) for item in db.execute(
        "SELECT * FROM provenance_activities WHERE project_id=? AND target_id=? ORDER BY id", (project, proposal_id))]
    # An acceptance must invalidate an earlier standalone-deletion preview. Its
    # canonical memory is independently retained until a thread forget is approved.
    state["accepted_assertions_precondition"] = [dict(item) for item in db.execute(
        "SELECT a.* FROM assertion_versions a JOIN provenance_activities p ON p.target_id=a.id "
        "WHERE p.project_id=? AND p.activity_type='proposal_acceptance' AND p.input_ids_json=? ORDER BY a.id",
        (project, canonical_json([proposal_id])))]
    return {
        "affected_set": {name: [{"id": item["id"]} for item in rows] for name, rows in state.items()},
        "state_digest": store.keyed_digest("proposal-purge-scope-v1", canonical_json(state)),
    }


def check_proposal_scope(store, preview):
    try:
        current = proposal_scope(store, preview["project_id"], preview["proposal_id"])
    except MemoryError as exc:
        if exc.code != "not_found":
            raise
        current = None
    if current is None or any(preview.get(key) != current[key] for key in ("affected_set", "state_digest")):
        raise MemoryError("stale_preview", "The affected proposal state changed. Request and approve a new preview.")


def purge_proposals(store, rows, sequence, disposition):
    """Caller holds the writer transaction; tombstone and erasure commit together.

    Proposal evidence is inline. Canonical evidence, feedback, recall results and
    acceptance provenance belong to assertion versions and are not draft copies.
    Thread forget removes those through its separately reviewed scope.
    """
    db = store.connection
    for row in rows:
        key_digest = delivery_digest(store, row["project_id"], row["source_agent"], row["idempotency_key"])
        db.execute(
            "INSERT OR IGNORE INTO proposal_tombstones(project_id,provider,delivery_digest,proposal_id,disposition,purged_seq) "
            "VALUES (?,?,?,?,?,?)",
            (row["project_id"], row["source_agent"], key_digest, row["id"], disposition, sequence))
        db.execute("DELETE FROM provenance_activities WHERE project_id=? AND target_id=?", (row["project_id"], row["id"]))
        # Reviews cascade. Nothing copies the erased subject, body, evidence,
        # locator, delivery key or request fingerprint to another durable table.
        db.execute("DELETE FROM proposals WHERE project_id=? AND id=?", (row["project_id"], row["id"]))
