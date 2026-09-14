"""One project/audience/recorded/valid eligibility contract for read projections.

Conflict state is derived from immutable versions, never from the legacy mutable
conflict cache. Recorded intervals are half open; valid intervals are inclusive.
"""
from dataclasses import dataclass
from typing import Optional

from .security import digest_json


ASSERTION_SELECT = (
    "SELECT a.*,t.subject,e.body AS evidence_body,e.locator AS evidence_locator,"
    "e.observed_at,e.trust_tier,e.source_agent"
)
ASSERTION_JOINS = (
    " JOIN claim_threads t ON t.id=a.thread_id LEFT JOIN evidence e ON e.id=a.evidence_id "
)


@dataclass(frozen=True)
class Eligibility:
    project: str
    provider: str
    recorded: int
    mode: str = "current"
    valid: Optional[str] = None

    def sql(self):
        conditions = ["a.project_id=?", "a.ingest_seq<=?"]
        args = [self.project, self.recorded]
        if self.provider != "user_control":
            conditions.append("EXISTS (SELECT 1 FROM assertion_disclosures ad "
                              "WHERE ad.assertion_id=a.id AND ad.provider IN (?, '*'))")
            args.append(self.provider)
        if self.mode == "current":
            conditions.append("(a.retired_seq IS NULL OR a.retired_seq>?)")
            args.append(self.recorded)
        if self.valid is not None:
            conditions.append("a.valid_precision!='unknown' AND (a.valid_from IS NULL OR a.valid_from<=?) "
                              "AND (a.valid_to IS NULL OR a.valid_to>=?)")
            args.extend([self.valid, self.valid])
        return " AND ".join(conditions), args

    def rows(self, db, extra="1", args=()):
        clause, values = self.sql()
        return db.execute(ASSERTION_SELECT + " FROM assertion_versions a" + ASSERTION_JOINS
                          + "WHERE " + clause + " AND " + extra + " ORDER BY a.ingest_seq,a.id",
                          values + list(args)).fetchall()

    def at_snapshot(self, row):
        result = dict(row)
        if result["retired_seq"] is None or result["retired_seq"] > self.recorded:
            result.update(lifecycle="active", retired_seq=None, retired_at=None)
        return result


def overlap(left, right):
    """Different bodies conflict only if both recorded and valid lifetimes overlap."""
    if left["body"] == right["body"]:
        return False
    for a, b in ((left, right), (right, left)):
        if a["retired_seq"] is not None and a["retired_seq"] <= b["ingest_seq"]:
            return False
        # Unknown valid time is conservatively unbounded, but never matches an
        # explicit valid instant (Eligibility.sql enforces that distinction).
        if a["valid_to"] is not None and b["valid_from"] is not None and a["valid_to"] < b["valid_from"]:
            return False
    return True


def conflict_groups(rows):
    """Connected disputes within one eligible thread; singleton/equal sets vanish."""
    parents = list(range(len(rows)))

    def root(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    for i, left in enumerate(rows):
        for j in range(i):
            if overlap(left, rows[j]):
                parents[root(i)] = root(j)
    groups = {}
    for i, row in enumerate(rows):
        groups.setdefault(root(i), []).append(row)
    return {
        "cnf_" + digest_json(sorted(row["id"] for row in members))[:24]: members
        for members in groups.values() if len(members) > 1
    }


def record_audience_change(db, project, recorded, assertion_ids):
    """Persist only an opaque sequence mapping for audiences affected by a change.

    These mappings survive forget without retaining assertion IDs or content.
    A correction is one event for each audience seeing its old or new version.
    """
    providers = set()
    for assertion_id in assertion_ids:
        providers.update(row[0] for row in db.execute(
            "SELECT provider FROM assertion_disclosures WHERE assertion_id=?", (assertion_id,)))
    if "*" in providers:
        providers.remove("*")
        providers.update(row[0] for row in db.execute(
            "SELECT DISTINCT provider FROM capabilities WHERE project_id=?", (project,)))
    for provider in sorted(providers):
        db.execute(
            "INSERT OR IGNORE INTO audience_sequences(project_id,provider,local_seq,recorded_seq) "
            "SELECT ?,?,coalesce(max(local_seq),0)+1,? FROM audience_sequences WHERE project_id=? AND provider=?",
            (project, provider, recorded, project, provider))
