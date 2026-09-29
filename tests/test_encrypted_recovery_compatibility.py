"""Prepared native integration proof; synthetic approval is not human presence."""

import tempfile
import unittest
from tests.database_dump import database_dump
from pathlib import Path

from continuum_memory import storage, storage_rotation
from continuum_memory.kernel import Kernel
from continuum_memory.recovery_journal import load_locators, persist_locator
from continuum_memory.results import recovery_locator
from continuum_memory.storage import Store, load_capability, paths
from fixtures.rotation import RotationVault, make_proof_keys, synthetic_approval


class EncryptedRecoveryCompatibilityTest(unittest.TestCase):
    def test_existing_durable_receipt_locator_survives_storage_key_rotation(self):
        storage._require_sqlcipher_runtime()
        with tempfile.TemporaryDirectory(prefix="continuum-recovery-proof-") as temporary:
            proof = Path(temporary) / "proof"
            make_proof_keys(proof)
            vault = RotationVault()
            try:
                files = paths(vault.home)
                token = load_capability(files["control"])["token"]
                before = Store(vault.home)
                try:
                    control = before.authenticate(token)
                    row = before.connection.execute("SELECT * FROM admin_results WHERE nonce=?",
                                                    (vault.receipt_locator["nonce"],)).fetchone()
                    locator = recovery_locator(before, control, row["nonce"], row["project_id"],
                                               vault.receipt_locator["preview_digest"])
                    persist_locator(vault.home, locator)
                    receipt = Kernel(before).admin_recover(control, locator)
                    receipts = list(before.connection.execute("SELECT * FROM admin_results ORDER BY nonce"))
                    receipts = [tuple(item) for item in receipts]
                    vault_id, audit_key = before.vault_id, before.audit_key
                    journal = load_locators(vault.home, nonce=locator["nonce"])
                finally:
                    before.close()
                with synthetic_approval(proof):
                    rotated = storage_rotation.rotate_storage_key(vault.home)
                self.assertEqual(rotated["status"], "rotated")
                self.assertNotEqual(files["storage_key"].read_bytes(), vault.old_key)
                after = Store(vault.home)
                try:
                    self.assertEqual((after.vault_id, after.audit_key), (vault_id, audit_key))
                    current = after.authenticate(token)
                    self.assertEqual(current["id"], control["id"])
                    self.assertEqual([tuple(item) for item in after.connection.execute(
                        "SELECT * FROM admin_results ORDER BY nonce")], receipts)
                    self.assertEqual(load_locators(vault.home, nonce=locator["nonce"]), journal)
                    original = tuple(database_dump(after.connection))
                    self.assertEqual(Kernel(after).admin_recover(current, locator), receipt)
                    self.assertEqual(tuple(database_dump(after.connection)), original)
                    self.assertEqual(after.verify_audit()["status"], "valid")
                finally:
                    after.close()
            finally:
                vault.close()
