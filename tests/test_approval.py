import fcntl
import json
import os
import subprocess
import tempfile
import time
import unittest
import xml.etree.ElementTree as ElementTree
from contextlib import nullcontext
from pathlib import Path
from unittest import mock

from continuum_memory.approval import (
    LINUX_APPROVAL_BOUNDARY,
    OS_APPROVAL_UNAVAILABLE_BOUNDARY,
    PROTOTYPE_APPROVAL_BOUNDARY,
    approval_payload,
    approval_request,
    encode_grant,
    private_key_path,
    public_key_path,
    sign_payload,
    validate_approval_request,
    verify_payload,
)
from continuum_memory.broker import LinuxPolkitApprovalBroker, broker_for_challenge
from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.polkit_helper import (
    _ensure_privileged_runtime,
    _provision_lock,
    _root_directory,
    authorize_request,
    provision_keys,
    render_preview,
    validate_installed_policy,
)
from continuum_memory.security import digest_json, sign_grant
from continuum_memory.storage import Store, load_capability, paths

ROOT = Path(__file__).resolve().parents[1]


def no_path_validation(_path, _label, **_options):
    return None


class ApprovalContractTest(unittest.TestCase):
    def challenge(self):
        preview = {
            "operation": "remember",
            "project_id": "prj_abcdefgh",
            "claim": "Synthetic approval fixture",
        }
        return {
            "approval_boundary": LINUX_APPROVAL_BOUNDARY,
            "expires_at": int(time.time()) + 60,
            "nonce": "gnt_abcdefgh",
            "operation": "remember",
            "preview": preview,
            "preview_digest": digest_json(preview),
            "vault_id": "vlt_abcdefgh",
        }

    def test_request_binds_exact_preview_expiry_vault_and_caller(self):
        challenge = self.challenge()
        request = approval_request(challenge, caller_uid=1234)
        self.assertEqual(request["caller_uid"], 1234)
        self.assertEqual(request["vault_id"], challenge["vault_id"])
        self.assertEqual(request["expires_at"], challenge["expires_at"])

        changed = dict(request)
        changed["preview"] = dict(request["preview"], claim="Changed after preview")
        with self.assertRaises(MemoryError) as mismatch:
            validate_approval_request(changed)
        self.assertEqual(mismatch.exception.code, "approval_mismatch")

        expired = dict(request, expires_at=int(time.time()) - 1)
        with self.assertRaises(MemoryError) as expiry:
            validate_approval_request(expired)
        self.assertEqual(expiry.exception.code, "approval_expired")

    def test_system_key_selection_is_bound_to_os_user_not_vault_metadata(self):
        self.assertEqual(public_key_path(1234).name, "uid-1234.pem")
        self.assertEqual(private_key_path(1234).name, "uid-1234.pem")
        self.assertNotIn("vlt_", str(public_key_path(1234)))

    def test_polkit_broker_uses_stdin_and_accepts_only_strict_response(self):
        calls = []
        grant = encode_grant(b"synthetic-signature")

        def runner(arguments, **options):
            calls.append((arguments, options))
            response = json.dumps({"grant": grant, "schema_version": 1}).encode("utf-8")
            return subprocess.CompletedProcess(arguments, 0, stdout=response)

        broker = LinuxPolkitApprovalBroker(
            helper_path=Path("/trusted/approval-helper"),
            pkexec_path=Path("/trusted/pkexec"),
            runner=runner,
            path_validator=no_path_validation,
            caller_uid=1234,
        )
        challenge = self.challenge()
        self.assertEqual(broker.authorize(challenge), grant)
        arguments, options = calls[0]
        self.assertEqual(arguments, ["/trusted/pkexec", "/trusted/approval-helper", "authorize"])
        self.assertNotIn(challenge["preview_digest"], " ".join(arguments))
        request = json.loads(options["input"].decode("utf-8"))
        self.assertEqual(request["preview"], challenge["preview"])
        self.assertEqual(request["caller_uid"], 1234)
        self.assertNotIn("continuum-memory/approval-keys", json.dumps(options["env"]))

    def test_polkit_broker_fails_closed_on_cancel_and_malformed_output(self):
        cases = [
            (126, b"", "cancelled"),
            (0, b"not-json", "approval_invalid"),
            (2, b"", "approval_broker_unavailable"),
        ]
        for returncode, output, expected_code in cases:
            with self.subTest(returncode=returncode, output=output):
                def runner(arguments, **_options):
                    return subprocess.CompletedProcess(arguments, returncode, stdout=output)

                broker = LinuxPolkitApprovalBroker(
                    helper_path=Path("/trusted/approval-helper"),
                    pkexec_path=Path("/trusted/pkexec"),
                    runner=runner,
                    path_validator=no_path_validation,
                    caller_uid=1234,
                )
                with self.assertRaises(MemoryError) as failure:
                    broker.authorize(self.challenge())
                self.assertEqual(failure.exception.code, expected_code)

    def test_privileged_helper_requires_matching_uid_and_confirmation(self):
        request = approval_request(self.challenge(), caller_uid=1234)
        signed = []

        def signer(caller_uid, payload):
            signed.append((caller_uid, payload))
            return encode_grant(b"helper-signature")

        result = authorize_request(request, 1234, confirmer=lambda _request: True, signer=signer)
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(len(signed), 1)
        self.assertEqual(signed[0][0], request["caller_uid"])

        with self.assertRaises(MemoryError) as wrong_uid:
            authorize_request(request, 4321, confirmer=lambda _request: True, signer=signer)
        self.assertEqual(wrong_uid.exception.code, "approval_invalid")
        with self.assertRaises(MemoryError) as cancelled:
            authorize_request(request, 1234, confirmer=lambda _request: False, signer=signer)
        self.assertEqual(cancelled.exception.code, "cancelled")

    def test_polkit_policy_requires_uncached_admin_auth_for_fixed_helper(self):
        policy = ElementTree.parse(
            str(ROOT / "packaging" / "linux" / "org.continuummemory.approval.policy")
        ).getroot()
        action = policy.find("./action[@id='org.continuummemory.approval']")
        self.assertIsNotNone(action)
        assert action is not None
        self.assertEqual(action.findtext("./defaults/allow_active"), "auth_admin")
        annotation = action.find("./annotate[@key='org.freedesktop.policykit.exec.path']")
        self.assertIsNotNone(annotation)
        assert annotation is not None
        self.assertEqual(annotation.text, "/usr/libexec/continuum-memory/approval-helper")
        wrapper = (ROOT / "packaging" / "linux" / "approval-helper").read_text(encoding="utf-8")
        self.assertIn("/opt/continuum-memory-polkit/bin/continuum-polkit-helper", wrapper)
        validate_installed_policy(
            ROOT / "packaging" / "linux" / "org.continuummemory.approval.policy",
            path_validator=no_path_validation,
        )

        with tempfile.TemporaryDirectory(prefix="continuum-policy-test-") as temporary:
            mutated = Path(temporary) / "approval.policy"
            policy_text = (
                ROOT / "packaging" / "linux" / "org.continuummemory.approval.policy"
            ).read_text(encoding="utf-8")
            mutations = {
                "permissive": policy_text.replace("auth_admin", "yes"),
                "redirected": policy_text.replace(
                    "/usr/libexec/continuum-memory/approval-helper", "/tmp/approval-helper"
                ),
            }
            for label, contents in mutations.items():
                with self.subTest(policy=label):
                    mutated.write_text(contents, encoding="utf-8")
                    with self.assertRaises(MemoryError) as unsafe:
                        validate_installed_policy(mutated, path_validator=no_path_validation)
                    self.assertEqual(unsafe.exception.code, "approval_broker_unsafe")

    def test_privileged_runtime_requires_policy_validation(self):
        with mock.patch("continuum_memory.polkit_helper.sys.platform", "linux"):
            with mock.patch("continuum_memory.polkit_helper.os.geteuid", return_value=0):
                with mock.patch("continuum_memory.polkit_helper.ensure_root_owned_regular"):
                    failure = MemoryError("approval_broker_unsafe", "Synthetic unsafe policy.")
                    with mock.patch(
                        "continuum_memory.polkit_helper.validate_installed_policy",
                        side_effect=failure,
                    ) as validate_policy:
                        with self.assertRaises(MemoryError) as rejected:
                            _ensure_privileged_runtime()
        validate_policy.assert_called_once_with()
        self.assertEqual(rejected.exception.code, "approval_broker_unsafe")

    def test_key_directory_symlink_is_rejected_before_chmod(self):
        with tempfile.TemporaryDirectory(prefix="continuum-key-directory-") as temporary:
            target = Path(temporary) / "target"
            target.mkdir()
            symlink = Path(temporary) / "approval-keys"
            symlink.symlink_to(target, target_is_directory=True)
            with mock.patch("continuum_memory.polkit_helper.os.chmod") as chmod:
                with self.assertRaises(MemoryError) as unsafe:
                    _root_directory(symlink, private=True)
            chmod.assert_not_called()
            self.assertEqual(unsafe.exception.code, "approval_broker_unsafe")

    def test_provisioning_uses_a_private_exclusive_lock(self):
        with tempfile.TemporaryDirectory(prefix="continuum-provision-lock-") as temporary:
            lock_path = Path(temporary) / ".provision.lock"
            with mock.patch("continuum_memory.polkit_helper.fcntl.flock") as flock:
                with _provision_lock(lock_path, expected_owner=os.getuid()):
                    info = lock_path.stat()
                    self.assertEqual(info.st_mode & 0o777, 0o600)
                flock.assert_called_once_with(mock.ANY, fcntl.LOCK_EX)

            target = Path(temporary) / "target"
            target.write_text("not a lock", encoding="utf-8")
            symlink = Path(temporary) / "unsafe.lock"
            symlink.symlink_to(target)
            with self.assertRaises(MemoryError) as unsafe:
                with _provision_lock(symlink, expected_owner=os.getuid()):
                    pass
            self.assertEqual(unsafe.exception.code, "approval_broker_unsafe")

    def test_provisioning_sanitizes_the_caller_umask_before_creating_directories(self):
        with mock.patch("continuum_memory.polkit_helper.os.umask", side_effect=[0o077, 0o022]) as umask:
            with mock.patch("continuum_memory.polkit_helper.private_key_path") as private_path:
                with mock.patch("continuum_memory.polkit_helper.public_key_path") as public_path:
                    private_path.return_value = Path("/private/uid-1234.pem")
                    public_path.return_value = Path("/public/uid-1234.pem")
                    with mock.patch("continuum_memory.polkit_helper._root_directory"):
                        with mock.patch(
                            "continuum_memory.polkit_helper._provision_lock",
                            return_value=nullcontext(),
                        ):
                            with mock.patch(
                                "continuum_memory.polkit_helper._provision_keys_locked",
                                return_value={"status": "provisioned"},
                            ):
                                self.assertEqual(provision_keys(1234), {"status": "provisioned"})
        self.assertEqual(umask.call_args_list, [mock.call(0o022), mock.call(0o077)])

    def test_preview_rendering_escapes_unicode_direction_controls(self):
        rendered = render_preview({"claim": "safe\u202eevil"})
        self.assertNotIn("\u202e", rendered)
        self.assertIn("\\u202e", rendered)

    def test_root_installer_ignores_caller_path_and_python_environment(self):
        installer = ROOT / "packaging" / "linux" / "install-polkit.sh"
        source = installer.read_text(encoding="utf-8")
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", source)
        self.assertIn("/usr/bin/readlink -f", source)
        self.assertIn("/usr/bin/python3 -I -m venv", source)
        self.assertIn("/usr/bin/env -i", source)
        self.assertIn("/opt/.continuum-memory-polkit-build.XXXXXX", source)
        self.assertIn('"$BUILD_DIRECTORY/bin/python" -I -m pip', source)
        self.assertNotIn('"$RUNTIME_DIRECTORY/bin/python" -I -m pip', source)
        self.assertIn("existing approval runtime is unsafe", source)
        if os.geteuid() == 0:
            self.skipTest("the non-root installer environment test must not mutate system paths")
        with tempfile.TemporaryDirectory(prefix="continuum-installer-path-") as temporary:
            fake_bin = Path(temporary) / "bin"
            fake_bin.mkdir()
            marker = Path(temporary) / "caller-path-was-used"
            fake_id = fake_bin / "id"
            fake_id.write_text(
                "#!/bin/sh\n/usr/bin/touch '%s'\necho 1\n" % marker,
                encoding="utf-8",
            )
            fake_id.chmod(0o755)
            environment = dict(os.environ)
            environment["PATH"] = str(fake_bin)
            environment["PYTHONPATH"] = str(fake_bin)
            result = subprocess.run(
                [str(installer)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=environment,
            )
            self.assertEqual(result.returncode, 2)
            self.assertFalse(marker.exists())


class AsymmetricApprovalIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="continuum-approval-test-")
        root = Path(self.temporary.name)
        self.private_key = root / "private.pem"
        self.public_key = root / "public.pem"
        subprocess.run(
            ["/usr/bin/openssl", "genrsa", "-out", str(self.private_key), "2048"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        subprocess.run(
            [
                "/usr/bin/openssl",
                "rsa",
                "-in",
                str(self.private_key),
                "-pubout",
                "-out",
                str(self.public_key),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        self.data_dir = root / "vault"
        bootstrap = Store.bootstrap(
            self.data_dir,
            [{"name": "alpha", "path_hint": "/fixture/alpha", "providers": ["codex"]}],
        )
        self.project = bootstrap["projects"][0]["id"]
        self.store = Store(self.data_dir)
        self.control = self.store.authenticate(load_capability(paths(self.data_dir)["control"])["token"])
        provider_capability = Path(bootstrap["projects"][0]["capabilities"]["codex"])
        self.agent = self.store.authenticate(load_capability(provider_capability)["token"])

        def verifier(public_key, payload, grant):
            return verify_payload(public_key, payload, grant, key_validator=no_path_validation)

        self.kernel = Kernel(
            self.store,
            approval_public_key_provider=lambda _caller_uid: self.public_key,
            approval_signature_verifier=verifier,
        )

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def _grant(self, challenge):
        payload = approval_payload(
            challenge["vault_id"],
            challenge["caller_uid"],
            challenge["nonce"],
            challenge["operation"],
            challenge["preview_digest"],
            challenge["expires_at"],
        )
        return sign_payload(self.private_key, payload, key_validator=no_path_validation)

    def _remember_challenge(self, subject):
        return self.kernel.admin_preview(
            self.control,
            {
                "operation": "remember",
                "project": self.project,
                "subject": subject,
                "claim": "The Linux broker uses a root-isolated signing key.",
            },
        )

    def test_kernel_requires_asymmetric_grant_and_records_broker_method(self):
        challenge = self._remember_challenge("linux approval")
        self.assertEqual(challenge["approval_boundary"], LINUX_APPROVAL_BOUNDARY)
        grant = self._grant(challenge)
        result = self.kernel.admin_apply(
            self.control,
            {
                "nonce": challenge["nonce"],
                "preview_digest": challenge["preview_digest"],
                "grant": grant,
                "preview": challenge["preview"],
            },
        )
        method = self.store.connection.execute(
            "SELECT method FROM attestations WHERE assertion_id=? AND role='authorizer'",
            (result["assertion_id"],),
        ).fetchone()[0]
        self.assertEqual(method, LINUX_APPROVAL_BOUNDARY)

        with self.assertRaises(MemoryError) as replay:
            self.kernel.admin_apply(
                self.control,
                {
                    "nonce": challenge["nonce"],
                    "preview_digest": challenge["preview_digest"],
                    "grant": grant,
                    "preview": challenge["preview"],
                },
            )
        self.assertEqual(replay.exception.code, "approval_replay")

    def test_kernel_rejects_legacy_hmac_when_linux_key_is_active(self):
        challenge = self._remember_challenge("legacy rejection")
        legacy = sign_grant(
            self.control["token"].encode("ascii"),
            challenge["nonce"],
            challenge["operation"],
            challenge["preview_digest"],
        )
        with self.assertRaises(MemoryError) as rejected:
            self.kernel.admin_apply(
                self.control,
                {
                    "nonce": challenge["nonce"],
                    "preview_digest": challenge["preview_digest"],
                    "grant": legacy,
                    "preview": challenge["preview"],
                },
            )
        self.assertEqual(rejected.exception.code, "approval_invalid")

    def test_signature_is_bound_to_exact_challenge(self):
        first = self._remember_challenge("first challenge")
        second = self._remember_challenge("second challenge")
        first_grant = self._grant(first)
        with self.assertRaises(MemoryError) as rejected:
            self.kernel.admin_apply(
                self.control,
                {
                    "nonce": second["nonce"],
                    "preview_digest": second["preview_digest"],
                    "grant": first_grant,
                    "preview": second["preview"],
                },
            )
        self.assertEqual(rejected.exception.code, "approval_invalid")

    def test_signature_rejects_cross_user_vault_operation_digest_and_expiry(self):
        challenge = self._remember_challenge("all signed fields")
        signed_fields = {
            "vault_id": challenge["vault_id"],
            "caller_uid": challenge["caller_uid"],
            "nonce": challenge["nonce"],
            "operation": challenge["operation"],
            "preview_digest": challenge["preview_digest"],
            "expires_at": challenge["expires_at"],
        }
        mutations = {
            "vault": {"vault_id": "vlt_other_vault"},
            "caller": {"caller_uid": challenge["caller_uid"] + 1},
            "nonce": {"nonce": "gnt_other_nonce"},
            "operation": {"operation": "forget"},
            "digest": {"preview_digest": "0" * 64},
            "expiry": {"expires_at": challenge["expires_at"] + 1},
        }
        for label, mutation in mutations.items():
            with self.subTest(field=label):
                fields = dict(signed_fields, **mutation)
                payload = approval_payload(**fields)
                grant = sign_payload(self.private_key, payload, key_validator=no_path_validation)
                with self.assertRaises(MemoryError) as rejected:
                    self.kernel.admin_apply(
                        self.control,
                        {
                            "nonce": challenge["nonce"],
                            "preview_digest": challenge["preview_digest"],
                            "grant": grant,
                            "preview": challenge["preview"],
                        },
                    )
                self.assertEqual(rejected.exception.code, "approval_invalid")

    def test_daemon_rejects_an_expired_signed_challenge(self):
        challenge = self._remember_challenge("expired signed challenge")
        expired_at = int(time.time()) - 1
        self.store.begin()
        self.store.connection.execute(
            "UPDATE admin_challenges SET expires_at=? WHERE nonce=?",
            (expired_at, challenge["nonce"]),
        )
        self.store.commit()
        payload = approval_payload(
            challenge["vault_id"],
            challenge["caller_uid"],
            challenge["nonce"],
            challenge["operation"],
            challenge["preview_digest"],
            expired_at,
        )
        grant = sign_payload(self.private_key, payload, key_validator=no_path_validation)
        with self.assertRaises(MemoryError) as rejected:
            self.kernel.admin_apply(
                self.control,
                {
                    "nonce": challenge["nonce"],
                    "preview_digest": challenge["preview_digest"],
                    "grant": grant,
                    "preview": challenge["preview"],
                },
            )
        self.assertEqual(rejected.exception.code, "approval_expired")

    def test_unprovisioned_runtime_fails_closed(self):
        kernel = Kernel(self.store, approval_public_key_provider=lambda _caller_uid: None)
        info = kernel.approval_info(self.control, {})
        self.assertEqual(info["approval_boundary"], OS_APPROVAL_UNAVAILABLE_BOUNDARY)
        self.assertFalse(info["linux_polkit_provisioned"])
        with self.assertRaises(MemoryError) as unavailable:
            kernel.admin_preview(
                self.control,
                {
                    "operation": "remember",
                    "project": self.project,
                    "subject": "must fail closed",
                    "claim": "No live prototype approval is allowed.",
                },
            )
        self.assertEqual(unavailable.exception.code, "approval_broker_unavailable")
        with self.assertRaises(MemoryError) as no_broker:
            broker_for_challenge({"approval_boundary": OS_APPROVAL_UNAVAILABLE_BOUNDARY})
        self.assertEqual(no_broker.exception.code, "approval_broker_unavailable")

    def test_prototype_mode_requires_explicit_test_injection(self):
        kernel = Kernel(
            self.store,
            approval_public_key_provider=lambda _caller_uid: None,
            allow_prototype_approval=True,
        )
        info = kernel.approval_info(self.control, {})
        self.assertEqual(info["approval_boundary"], PROTOTYPE_APPROVAL_BOUNDARY)
        self.assertFalse(info["linux_polkit_provisioned"])

    def test_agent_capability_cannot_read_approval_configuration(self):
        with self.assertRaises(MemoryError) as forbidden:
            self.kernel.approval_info(self.agent, {})
        self.assertEqual(forbidden.exception.code, "forbidden")


if __name__ == "__main__":
    unittest.main()
