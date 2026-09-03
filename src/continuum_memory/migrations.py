"""Forward-only schema for the prototype canonical ledger."""

SCHEMA_VERSION = 2

SCHEMA_SQL = r"""
PRAGMA application_id = 1129143636;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS sequence (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    value INTEGER NOT NULL CHECK (value >= 0)
) STRICT;
INSERT OR IGNORE INTO sequence(singleton, value) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    path_hint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_seq INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('project','repository','worktree','branch','path','symbol','task','session')),
    value TEXT NOT NULL,
    UNIQUE(project_id, kind, value)
) STRICT;

CREATE TABLE IF NOT EXISTS capabilities (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    permissions_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    body_fingerprint TEXT NOT NULL,
    locator TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    trust_tier TEXT NOT NULL CHECK (trust_tier IN ('user_authored','agent_provided','fixture')),
    source_agent TEXT NOT NULL,
    created_seq INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS claim_threads (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_seq INTEGER NOT NULL,
    UNIQUE(project_id, subject_key)
) STRICT;

CREATE TABLE IF NOT EXISTS assertion_versions (
    id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL REFERENCES claim_threads(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    evidence_id TEXT REFERENCES evidence(id) ON DELETE SET NULL,
    body TEXT NOT NULL,
    admission TEXT NOT NULL CHECK (admission IN ('accepted')),
    epistemic TEXT NOT NULL CHECK (epistemic IN ('asserted','verified','disputed','refuted')),
    lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active','superseded','retracted','expired')),
    authority TEXT NOT NULL CHECK (authority = 'data'),
    classification TEXT NOT NULL CHECK (classification IN ('public','internal','confidential','restricted')),
    retention TEXT NOT NULL,
    valid_precision TEXT NOT NULL CHECK (valid_precision IN ('unknown','instant','open','interval')),
    valid_from TEXT,
    valid_to TEXT,
    recorded_at TEXT NOT NULL,
    ingest_seq INTEGER NOT NULL UNIQUE,
    retired_at TEXT,
    retired_seq INTEGER,
    created_by TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS assertion_disclosures (
    assertion_id TEXT NOT NULL REFERENCES assertion_versions(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    PRIMARY KEY(assertion_id, provider)
) STRICT;

CREATE TABLE IF NOT EXISTS evidence_refs (
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    assertion_id TEXT NOT NULL REFERENCES assertion_versions(id) ON DELETE CASCADE,
    PRIMARY KEY(evidence_id, assertion_id)
) STRICT;

CREATE TABLE IF NOT EXISTS proposals (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    body TEXT NOT NULL,
    evidence_body TEXT NOT NULL,
    evidence_locator TEXT NOT NULL,
    classification TEXT NOT NULL,
    retention TEXT NOT NULL,
    disclosure_json TEXT NOT NULL,
    valid_precision TEXT NOT NULL,
    valid_from TEXT,
    valid_to TEXT,
    status TEXT NOT NULL CHECK (status IN ('proposed','accepted','rejected')),
    source_agent TEXT NOT NULL,
    source_capability_id TEXT NOT NULL REFERENCES capabilities(id),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_seq INTEGER NOT NULL,
    reviewed_at TEXT,
    accepted_assertion_id TEXT REFERENCES assertion_versions(id),
    UNIQUE(source_capability_id, idempotency_key)
) STRICT;

CREATE TABLE IF NOT EXISTS attestations (
    id TEXT PRIMARY KEY,
    assertion_id TEXT NOT NULL REFERENCES assertion_versions(id) ON DELETE CASCADE,
    principal TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('author','recorder','authorizer','validator')),
    method TEXT NOT NULL,
    attested_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS provenance_activities (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_id TEXT NOT NULL,
    activity_type TEXT NOT NULL CHECK (activity_type IN ('agent_proposal','user_remember','proposal_acceptance','user_correction')),
    actor TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    input_ids_json TEXT NOT NULL,
    output_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_seq INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS consent_receipts (
    id TEXT PRIMARY KEY,
    assertion_id TEXT NOT NULL REFERENCES assertion_versions(id) ON DELETE CASCADE,
    payload_digest TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    classification TEXT NOT NULL,
    retention TEXT NOT NULL,
    disclosure_json TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    authorized_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS reviews (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES proposals(id) ON DELETE CASCADE,
    decision TEXT NOT NULL CHECK (decision IN ('accepted','rejected')),
    actor TEXT NOT NULL,
    preview_digest TEXT NOT NULL,
    reviewed_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS relations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    from_assertion_id TEXT NOT NULL REFERENCES assertion_versions(id) ON DELETE CASCADE,
    to_assertion_id TEXT NOT NULL REFERENCES assertion_versions(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('supports','contradicts','supersedes','derived_from','applies_to')),
    created_seq INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS conflicts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    thread_id TEXT NOT NULL REFERENCES claim_threads(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('open','resolved')),
    created_seq INTEGER NOT NULL,
    resolved_seq INTEGER
) STRICT;

CREATE TABLE IF NOT EXISTS conflict_members (
    conflict_id TEXT NOT NULL REFERENCES conflicts(id) ON DELETE CASCADE,
    assertion_id TEXT NOT NULL REFERENCES assertion_versions(id) ON DELETE CASCADE,
    PRIMARY KEY(conflict_id, assertion_id)
) STRICT;

CREATE TABLE IF NOT EXISTS task_states (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    objective TEXT NOT NULL,
    state TEXT NOT NULL,
    blockers_json TEXT NOT NULL,
    next_actions_json TEXT NOT NULL,
    owners_json TEXT NOT NULL,
    revision INTEGER NOT NULL,
    expires_at TEXT,
    ingest_seq INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS feedback (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    recall_id TEXT NOT NULL,
    assertion_id TEXT NOT NULL,
    label TEXT NOT NULL CHECK (label IN ('helpful','irrelevant','stale','wrong','unsafe','missing')),
    reason TEXT NOT NULL,
    source_capability_id TEXT NOT NULL REFERENCES capabilities(id),
    created_at TEXT NOT NULL,
    created_seq INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS recalls (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    query_digest TEXT NOT NULL,
    result_ids_json TEXT NOT NULL,
    watermark INTEGER NOT NULL,
    allows_historical INTEGER NOT NULL CHECK (allows_historical IN (0,1)),
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS admin_challenges (
    nonce TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    project_id TEXT NOT NULL,
    preview_json TEXT NOT NULL,
    preview_digest TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at TEXT
) STRICT;

CREATE TABLE IF NOT EXISTS deletion_receipts (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    projection_kinds_json TEXT NOT NULL,
    deletion_seq INTEGER NOT NULL,
    completion_state TEXT NOT NULL CHECK (completion_state = 'complete'),
    policy_version TEXT NOT NULL,
    deleted_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS audit_events (
    audit_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_seq INTEGER NOT NULL,
    actor_kind TEXT NOT NULL,
    operation TEXT NOT NULL,
    scoped_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    policy_decision TEXT NOT NULL,
    result TEXT NOT NULL,
    key_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    previous_mac TEXT NOT NULL,
    mac TEXT NOT NULL
) STRICT;

CREATE VIRTUAL TABLE IF NOT EXISTS assertion_fts USING fts5(
    assertion_id UNINDEXED,
    project_id UNINDEXED,
    subject,
    body,
    tokenize = 'unicode61'
);

CREATE INDEX IF NOT EXISTS idx_assertions_current
ON assertion_versions(project_id, lifecycle, ingest_seq, retired_seq);
CREATE INDEX IF NOT EXISTS idx_disclosures_provider
ON assertion_disclosures(provider, assertion_id);
CREATE INDEX IF NOT EXISTS idx_proposals_inbox
ON proposals(project_id, status, created_seq);
CREATE INDEX IF NOT EXISTS idx_conflicts_open
ON conflicts(project_id, status, thread_id);
CREATE INDEX IF NOT EXISTS idx_provenance_target
ON provenance_activities(project_id, target_id, created_seq);
"""
