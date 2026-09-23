"""Read-only audit verification shared by live and encrypted-backup snapshots.

The caller owns transaction/serialization and supplies an authenticated anchor
loader. This verifies integrity and a presented prefix, not independent freshness.
It never creates, repairs or advances an anchor.
"""

import hashlib
import hmac

from .errors import MemoryError
from .security import canonical_json


def verify_audit_snapshot(connection, audit_key, load_anchor):
    previous = "GENESIS"
    count = 0
    last_seq = 0
    for row in connection.execute("SELECT * FROM audit_events ORDER BY audit_seq"):
        count += 1
        last_seq = int(row["audit_seq"])
        if row["previous_mac"] != previous:
            return {"status": "invalid_internal_link", "first_invalid_audit_seq": row["audit_seq"]}
        payload = {
            "actor_kind": row["actor_kind"],
            "event_seq": row["event_seq"],
            "key_id": row["key_id"],
            "occurred_at": row["occurred_at"],
            "operation": row["operation"],
            "policy_decision": row["policy_decision"],
            "result": row["result"],
            "scoped_id": row["scoped_id"],
            "target_id": row["target_id"],
        }
        expected = hmac.new(
            audit_key,
            (previous + "\n" + canonical_json(payload)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, row["mac"]):
            return {"status": "invalid_event_mac", "first_invalid_audit_seq": row["audit_seq"]}
        previous = row["mac"]
    try:
        anchor = load_anchor()
    except (OSError, ValueError, RecursionError, MemoryError):
        return {"status": "anchor_unavailable", "events": count}
    if (not isinstance(anchor, dict) or set(anchor) != {"audit_seq", "mac"}
            or type(anchor["audit_seq"]) is not int or anchor["audit_seq"] < 0
            or not isinstance(anchor["mac"], str)):
        return {"status": "anchor_malformed", "events": count}
    anchor_seq = anchor["audit_seq"]
    if (anchor_seq == 0 and anchor["mac"] != "GENESIS") or (anchor_seq > 0 and
            (len(anchor["mac"]) != 64 or any(ch not in "0123456789abcdef" for ch in anchor["mac"]))):
        return {"status": "anchor_malformed", "events": count}
    if anchor_seq > last_seq:
        return {"status": "database_tail_rollback", "events": count, "anchor_audit_seq": anchor_seq}
    anchored = connection.execute("SELECT mac FROM audit_events WHERE audit_seq=?", (anchor_seq,)).fetchone()
    prefix_mac = "GENESIS" if anchor_seq == 0 else (anchored[0] if anchored else "")
    if not hmac.compare_digest(anchor["mac"], prefix_mac):
        return {"status": "anchor_mismatch", "events": count}
    if anchor_seq < last_seq:
        return {"status": "external_anchor_stale", "events": count, "anchor_audit_seq": anchor_seq}
    return {"status": "valid", "events": count, "head": previous}
