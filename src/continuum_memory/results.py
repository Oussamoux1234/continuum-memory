"""Immutable, content-free receipts for already-approved owner operations."""

import hmac
import json

from .errors import MemoryError, NOT_FOUND
from .recovery_locator import validate_locator
from .security import canonical_json, now_iso


def _payload(row):
    return canonical_json({key: row[key] for key in (
        "nonce", "capability_id", "project_id", "operation", "preview_key", "result_json", "created_at")})


def _binding(store, nonce, capability_id, project_id, digest):
    # A raw preview hash permits offline guesses of forgotten low-entropy text.
    return store.keyed_digest("admin-result-request-v1", canonical_json([nonce, capability_id, project_id, digest]))


def recovery_locator(store, capability, nonce, project_id, preview_digest):
    # The daemon has already authenticated the control capability. This selector
    # can persist without retaining a content-guessable raw preview digest.
    preview_key = _binding(store, nonce, capability["id"], project_id, preview_digest)
    return {"version": 1, "vault_id": store.vault_id, "nonce": nonce,
            "binding": _recovery_binding(store, nonce, capability["id"], preview_key)}


def _recovery_binding(store, nonce, capability_id, preview_key):
    # Bind the persisted descriptor to the current vault as well as the legacy
    # receipt selector. Relabeling a copied vault must not retarget a locator.
    return store.keyed_digest("admin-recovery-locator-v1",
                              canonical_json([1, store.vault_id, nonce, capability_id, preview_key]))


def save_result(store, capability, challenge, result):
    # Only kernel-generated administrative RESULT metadata reaches this path.
    # Do not store previews, grants, caller bodies, evidence, reasons or errors.
    row = {"nonce": challenge["nonce"], "capability_id": capability["id"],
           "project_id": challenge["project_id"], "operation": challenge["operation"],
           "preview_key": _binding(store, challenge["nonce"], capability["id"], challenge["project_id"],
                                   challenge["preview_digest"]), "result_json": canonical_json(result),
           "created_at": now_iso()}
    mac = store.keyed_digest("admin-result-v1", _payload(row))
    store.connection.execute(
        "INSERT INTO admin_results(nonce,capability_id,project_id,operation,preview_key,result_json,receipt_mac,created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (row["nonce"], row["capability_id"], row["project_id"], row["operation"],
         row["preview_key"], row["result_json"], mac, row["created_at"]))


def read_result(store, capability, nonce, preview_digest):
    row = store.connection.execute(
        "SELECT * FROM admin_results WHERE nonce=? AND capability_id=?",
        (nonce, capability["id"])).fetchone()
    if row is None:
        raise NOT_FOUND
    expected = _binding(store, nonce, capability["id"], row["project_id"], preview_digest)
    if not hmac.compare_digest(expected, row["preview_key"]):
        raise NOT_FOUND
    return _verified_result(store, row)


def read_recovery_result(store, capability, value):
    locator = validate_locator(value)
    if locator["vault_id"] != store.vault_id:
        raise NOT_FOUND
    row = store.connection.execute(
        "SELECT * FROM admin_results WHERE nonce=? AND capability_id=?",
        (locator["nonce"], capability["id"])).fetchone()
    if row is None:
        raise NOT_FOUND
    expected = _recovery_binding(store, locator["nonce"], capability["id"], row["preview_key"])
    if not hmac.compare_digest(locator["binding"], expected):
        raise NOT_FOUND
    return _verified_result(store, row)


def _verified_result(store, row):
    if not hmac.compare_digest(store.keyed_digest("admin-result-v1", _payload(row)), row["receipt_mac"]):
        raise MemoryError("integrity_error", "The operation receipt failed integrity verification.")
    return {"receipt_id": row["nonce"], "operation": row["operation"], "committed": True,
            "result": json.loads(row["result_json"]), "audit_anchor": store.verify_audit()["status"]}
