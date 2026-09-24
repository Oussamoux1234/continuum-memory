"""Synthetic credentials only; exercise admission before persistence, not DLP promises."""

import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from continuum_memory.admission import AdmissionPolicy, POLICY_FILE
from continuum_memory.errors import MemoryError
from continuum_memory.kernel import Kernel
from continuum_memory.security import canonical_json, create_private_directory, replace_private, require_keys
from continuum_memory.storage import Store, load_capability
from fixtures.harness import EphemeralHarness, private_test_home
from fixtures.windows_acl import set_fixture_acl
from tests import test_snapshot_forget as fixture

SECRETS = {
    'aws_access': 'AKIA' + 'ABCDEFGHIJKLMNOP',
    'aws_session': 'ASIA' + 'ABCDEFGHIJKLMNOP',
    'github_classic': 'ghp_' + 'A1b2C3d4' * 5,
    'github_fine': 'github_pat_' + 'A1b2C3d4' * 9,
    'api_key': 'sk-proj-' + 'A1b2C3d4' * 5,
    'slack': 'xoxb-' + '1234567890-' * 3 + 'abcdefghijklmnop',
    'pem': '-----BEGIN PRIVATE KEY-----\nsynthetic-only\n-----END PRIVATE KEY-----',
    'encrypted_pem': '-----BEGIN ENCRYPTED PRIVATE KEY-----\nsynthetic-only',
    'dsa': '-----BEGIN DSA PRIVATE KEY-----\nsynthetic-only',
    'pgp': '-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-only',
    'bearer': 'Authorization: Bearer ' + 'A1b2C3d4' * 5,
    'basic': 'Authorization: Basic ' + 'dXNlcjpzeW50aGV0aWMtcGFzc3dvcmQ=',
    'jwt': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.' + 'A1b2C3d4' * 4,
    'password': 'password = "Synthetic123456!"',
    'client_secret': '{"client_secret": "Synthetic123456!"}',
    'credential_url': 'https://fixture:synthetic-password@example.invalid/path',
}


def policy_file(home, **settings):
    path = home / POLICY_FILE
    replace_private(path, canonical_json(dict(version=1, **settings)).encode('utf-8'))
    return path


class DetectorTests(unittest.TestCase):
    def test_default_credential_families_and_fixed_errors(self):
        for family, secret in SECRETS.items():
            with self.subTest(family=family):
                with self.assertRaises(MemoryError) as caught:
                    AdmissionPolicy().check([secret])
                self.assertEqual(caught.exception.code, 'secret_rejected')
                self.assertNotIn(secret, str(caught.exception.as_dict()))
                self.assertLess(len(canonical_json(caught.exception.as_dict())), 160)

    def test_benign_lookalikes_and_placeholders(self):
        for text in ('Use API keys from the approved secret manager.', 'AKIA-short', 'ghp_short', 'sk-short',
                     'github_pat_<redacted>', 'Authorization: Bearer <token>', 'password=${PASSWORD}',
                     'client_secret = placeholder', 'https://user@example.invalid/path',
                     '-----BEGIN PUBLIC KEY-----', '-----BEGIN CERTIFICATE-----', 'xoxb-example',
                     'Bearer authentication requires separate authorization.'):
            with self.subTest(text=text):
                AdmissionPolicy().check([text])

    def test_boundary_prefixes_and_no_unknown_field_echo(self):
        secret = SECRETS['github_fine']
        for surrounding in (secret, 'prefix_' + secret, '(' + secret + ')', '\n' + secret):
            with self.assertRaises(MemoryError):
                AdmissionPolicy().check([surrounding])
        with self.assertRaises(MemoryError) as caught:
            require_keys({secret: 'ignored'}, ['subject'])
        self.assertNotIn(secret, canonical_json(caught.exception.as_dict()))


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='continuum-policy-test-')
        self.home = private_test_home(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def test_default_and_exact_owner_exception_bytes(self):
        self.assertEqual(AdmissionPolicy.load(self.home), AdmissionPolicy())
        lookalike = SECRETS['github_fine']
        digest = hashlib.sha256(lookalike.encode()).hexdigest()
        policy_file(self.home, allow_sha256=[digest], deny_literals=['synthetic-deny'])
        policy = AdmissionPolicy.load(self.home)
        policy.check([lookalike])
        for changed in (lookalike + ' ', 'prefix ' + lookalike, 'synthetic-deny'):
            with self.assertRaises(MemoryError):
                policy.check([changed])
        with self.assertRaises((AttributeError, TypeError)):
            policy.allow_sha256 = frozenset()
        policy_file(self.home)  # Existing instance is an immutable startup snapshot.
        policy.check([lookalike])
        with self.assertRaises(MemoryError):
            AdmissionPolicy.load(self.home).check([lookalike])

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'FIFO file safety')
    def test_raced_fifo_is_rejected_without_blocking(self):
        os.mkfifo(self.home / POLICY_FILE, 0o600)
        # Simulate replacement after successful path validation. The actual open
        # and descriptor validation still run against a real FIFO in a process.
        program = """import sys
from pathlib import Path
from continuum_memory import admission
from continuum_memory.errors import MemoryError
admission.ensure_private_regular = lambda *args: None
try:
    admission.AdmissionPolicy.load(Path(sys.argv[1]))
except MemoryError as exc:
    print(exc.code)
else:
    raise SystemExit(1)
"""
        result = subprocess.run([sys.executable, '-c', program, str(self.home)],
                                capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), b'admission_policy_invalid')
        self.assertEqual(result.stderr, b'')

    def test_invalid_or_unsafe_policy_fails_closed_without_diagnostics(self):
        cases = [b'not-json-private-sentinel', b'{"version":1,"version":1}',
                 b'{"version":true}', b'{"version":2}', b'{"version":1,"disabled":true}',
                 b'{"version":1,"allow_sha256":["private-sentinel"]}',
                 b'{"version":1,"deny_literals":["a"]}', b'{"version":1,"deny_literals":[[]]}',
                 json.dumps({'version':1,'deny_literals':['entry-%02d' % i for i in range(33)]}).encode(),
                 b' ' * 16385]
        path = self.home / POLICY_FILE
        for raw in cases:
            replace_private(path, raw)
            with self.subTest(case=cases.index(raw)):
                with self.assertRaises(MemoryError) as caught:
                    AdmissionPolicy.load(self.home)
                self.assertEqual(caught.exception.code, 'admission_policy_invalid')
                self.assertNotIn('private-sentinel', str(caught.exception.as_dict()))
                self.assertTrue(caught.exception.__suppress_context__)
        policy_file(self.home)
        if os.name == 'nt':
            set_fixture_acl(path, broad=True)
        else:
            os.chmod(path, 0o644)
        with self.assertRaises(MemoryError):
            AdmissionPolicy.load(self.home)
        if os.name == 'nt':
            set_fixture_acl(path)
        else:
            os.chmod(path, 0o600)
        linked = self.home / 'policy-hardlink'
        os.link(path, linked)
        with self.assertRaises(MemoryError):
            AdmissionPolicy.load(self.home)
        linked.unlink()
        path.rename(linked)
        path.symlink_to(linked)
        with self.assertRaises(MemoryError):
            AdmissionPolicy.load(self.home)
        path.unlink()
        path.mkdir(mode=0o700)
        with self.assertRaises(MemoryError):
            AdmissionPolicy.load(self.home)
        path.rmdir()
        if hasattr(os, 'mkfifo'):
            os.mkfifo(path, 0o600)
            with self.assertRaises(MemoryError):
                AdmissionPolicy.load(self.home)


class WriteAdmissionTests(unittest.TestCase):
    setUp = fixture.SnapshotForgetTest.setUp
    tearDown = fixture.SnapshotForgetTest.tearDown
    apply = fixture.SnapshotForgetTest.apply
    approve = fixture.SnapshotForgetTest.approve
    remember = fixture.SnapshotForgetTest.remember

    def reload(self):
        self.kernel = Kernel(self.store, now_provider=lambda: self.now,
                             approval_public_key_provider=lambda uid: None, allow_prototype_approval=True)

    def proposal(self, **updates):
        value = {'subject':'Synthetic subject', 'claim':'Synthetic claim.', 'evidence':'Synthetic evidence.',
                 'source_handle':'fixture:admission', 'disclosure':['codex'], 'idempotency_key':'delivery-admission'}
        value.update(updates)
        return value

    def clean(self, secret):
        self.assertNotIn(secret, '\n'.join(self.store.connection.iterdump()))
        for path in self.home.iterdir():
            if path.is_file() and path.name != POLICY_FILE:
                self.assertNotIn(secret.encode(), path.read_bytes(), path.name)

    def denied(self, action, secret):
        before = self.store.connection.total_changes
        sequence = self.store.connection.execute('SELECT value FROM sequence').fetchone()[0]
        with self.assertRaises(MemoryError) as caught:
            action()
        self.assertEqual(caught.exception.code, 'secret_rejected')
        self.assertNotIn(secret, str(caught.exception.as_dict()))
        self.assertEqual(sequence, self.store.connection.execute('SELECT value FROM sequence').fetchone()[0])
        self.assertEqual(before, self.store.connection.total_changes)
        self.clean(secret)

    def test_proposal_all_free_text_fields_and_delivery_key(self):
        for field in ('subject','claim','evidence','source_handle','idempotency_key'):
            secret = SECRETS['github_fine']
            with self.subTest(field=field):
                self.denied(lambda: self.kernel.propose(self.codex, self.proposal(**{field:secret})), secret)
        for family, secret in SECRETS.items():
            with self.subTest(family=family):
                self.denied(lambda: self.kernel.propose(self.codex, self.proposal(claim=secret)), secret)

    def test_remember_and_correction_fields_before_challenge(self):
        saved = self.remember()
        for operation in ('remember','correct'):
            for field in ('claim','evidence','evidence_locator') + (('subject',) if operation == 'remember' else ()):
                params = {'operation':operation,'project':self.project,'subject':'New subject','claim':'New claim.',
                          'target_id':saved['assertion_id'], field:SECRETS['github_fine']}
                with self.subTest(operation=operation, field=field):
                    self.denied(lambda: self.kernel.admin_preview(self.control, params), SECRETS['github_fine'])

    def test_feedback_before_persistence_and_no_request_override(self):
        saved = self.remember()
        receipt = self.kernel.search(self.codex, {'query':'engine'})
        base = {'recall_id':receipt['recall_id'],'item_id':saved['assertion_id'],'label':'wrong'}
        for secret in (SECRETS['bearer'], SECRETS['client_secret']):
            self.denied(lambda: self.kernel.feedback(self.codex, dict(base, reason=secret)), secret)
        with self.assertRaises(MemoryError) as caught:
            self.kernel.propose(self.codex, self.proposal(claim=SECRETS['github_fine'], allow_secret=True))
        self.assertEqual(caught.exception.code, 'unknown_field')
        self.clean(SECRETS['github_fine'])

    def test_custom_denies_cover_metadata_and_content(self):
        marker = 'private-marker'
        policy_file(self.home, deny_literals=[marker]); self.reload()
        for field in ('subject','claim','evidence','source_handle','idempotency_key','disclosure'):
            value = [marker] if field == 'disclosure' else marker
            self.denied(lambda: self.kernel.propose(self.codex, self.proposal(**{field:value})), marker)
        changed_capability = dict(self.codex, provider=marker)
        self.denied(lambda: self.kernel.propose(changed_capability, self.proposal()), marker)
        for operation in ('remember',):
            self.denied(lambda: self.kernel.admin_preview(self.control, {'operation':operation,'project':self.project,
                         'subject':marker,'claim':'Synthetic claim.'}), marker)

    def test_legacy_proposal_rechecked_but_cleanup_remains_possible(self):
        secret = SECRETS['github_fine']
        policy_file(self.home, allow_sha256=[hashlib.sha256(secret.encode()).hexdigest()]); self.reload()
        proposal = self.kernel.propose(self.codex, self.proposal(claim=secret))
        policy_file(self.home); self.reload()
        before = self.store.connection.execute('SELECT count(*) FROM admin_challenges').fetchone()[0]
        with self.assertRaises(MemoryError) as caught:
            self.kernel.admin_preview(self.control, {'operation':'accept_proposal','project':self.project,
                                                    'proposal_id':proposal['proposal_id']})
        self.assertEqual(caught.exception.code, 'secret_rejected')
        self.assertNotIn(secret, str(caught.exception.as_dict()))
        self.assertEqual(before, self.store.connection.execute('SELECT count(*) FROM admin_challenges').fetchone()[0])
        self.approve(operation='reject_proposal', proposal_id=proposal['proposal_id'])
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM proposals').fetchone()[0], 0)

    def test_apply_rechecks_tightened_policy_without_consuming_grant(self):
        secret = SECRETS['github_fine']
        policy_file(self.home, allow_sha256=[hashlib.sha256(secret.encode()).hexdigest()]); self.reload()
        challenge = self.kernel.admin_preview(self.control, {'operation':'remember','project':self.project,
                                                            'subject':'Policy drift','claim':secret})
        policy_file(self.home); self.reload()
        with self.assertRaises(MemoryError) as caught:
            self.apply(challenge)
        self.assertEqual(caught.exception.code, 'secret_rejected')
        self.assertIsNone(self.store.connection.execute('SELECT used_at FROM admin_challenges WHERE nonce=?',
                                                        (challenge['nonce'],)).fetchone()[0])
        self.clean(secret)
        for table in ('assertion_versions','evidence','assertion_fts','provenance_activities','consent_receipts'):
            self.assertEqual(self.store.connection.execute('SELECT count(*) FROM '+table).fetchone()[0], 0)

    def test_inherited_subject_is_rechecked_and_forget_stays_available(self):
        secret = SECRETS['github_fine']
        policy_file(self.home, allow_sha256=[hashlib.sha256(secret.encode()).hexdigest()]); self.reload()
        saved = self.remember(subject=secret)
        policy_file(self.home); self.reload()
        with self.assertRaises(MemoryError) as caught:
            self.kernel.admin_preview(self.control, {'operation':'correct','project':self.project,
                          'target_id':saved['assertion_id'],'claim':'A new harmless claim.'})
        self.assertEqual(caught.exception.code, 'secret_rejected')
        self.approve(operation='forget', target_id=saved['assertion_id'])
        self.assertEqual(self.store.connection.execute('SELECT count(*) FROM assertion_versions').fetchone()[0], 0)


class BootstrapAndDiagnosticTests(unittest.TestCase):
    def test_bootstrap_metadata_rejected_before_any_file_creation(self):
        with tempfile.TemporaryDirectory(prefix='continuum-bootstrap-admission-') as temporary:
            home = Path(temporary) / 'vault'
            for field in ('name','path_hint','providers'):
                # A short lower-case configured provider remains syntactically valid.
                secret = 'private-marker' if field == 'providers' else SECRETS['github_fine']
                if field == 'providers':
                    create_private_directory(home); policy_file(home, deny_literals=[secret])
                spec = {'name':'fixture','path_hint':'/synthetic/fixture','providers':['codex']}
                spec[field] = [secret] if field == 'providers' else secret
                with self.assertRaises(MemoryError) as caught:
                    Store.bootstrap(home,[spec])
                self.assertEqual(caught.exception.code,'secret_rejected')
                self.assertFalse((home/'continuum.db').exists())
                self.assertFalse((home/'audit.key').exists())
                self.assertFalse((home/'capabilities').exists())

    def test_argument_errors_never_echo_inputs_and_keep_stdout_empty(self):
        root = Path(__file__).resolve().parents[1]
        env = dict(os.environ, PYTHONPATH=str(root/'src'), PYTHONPYCACHEPREFIX=str(root/'work/pycache'))
        secret = SECRETS['github_fine']
        cases = [('continuum_memory.cli',[secret]), ('continuum_memory.cli',['search','--limit',secret]),
                 ('continuum_memory.cli',['audit',secret]), ('continuum_memory.daemon',['--'+secret]),
                 ('continuum_memory.mcp',['--'+secret])]
        for module,args in cases:
            with self.subTest(module=module,args_kind=len(args)):
                result = subprocess.run([sys.executable,'-m',module]+args,env=env,capture_output=True,timeout=5)
                self.assertEqual(result.returncode,2)
                self.assertEqual(result.stdout,b'')
                self.assertNotIn(secret.encode(),result.stderr)
                self.assertLess(len(result.stderr),160)
                self.assertEqual(json.loads(result.stderr)['error']['code'],'invalid_arguments')

    def test_filesystem_errors_are_bounded_and_do_not_echo_paths(self):
        root = Path(__file__).resolve().parents[1]
        env = dict(os.environ, PYTHONPATH=str(root/'src'), PYTHONPYCACHEPREFIX=str(root/'work/pycache'))
        secret = SECRETS['github_fine']
        with tempfile.TemporaryDirectory(prefix='continuum-error-admission-') as temporary:
            path = str(Path(temporary) / (secret * 4))
            cases = [('continuum_memory.cli', ['--data-dir',path,'init','--project-name','fixture',
                                              '--project-path','/synthetic/fixture']),
                     ('continuum_memory.daemon', ['--data-dir',path]),
                     ('continuum_memory.mcp', ['--data-dir',path,'--capability-file',path])]
            for module, args in cases:
                with self.subTest(module=module):
                    result = subprocess.run([sys.executable,'-m',module]+args,env=env,capture_output=True,timeout=5)
                    self.assertEqual(result.returncode,2)
                    combined = result.stdout + result.stderr
                    self.assertNotIn(secret.encode(),combined)
                    self.assertNotIn(b'Traceback',combined)
                    self.assertLess(len(combined),160)
                    expected = 'unsafe_windows_path' if os.name == 'nt' else 'local_io_error'
                    self.assertEqual(json.loads(combined)['error']['code'], expected)
            self.assertEqual(list(Path(temporary).iterdir()), [])

    @unittest.skipUnless(hasattr(socket,'AF_UNIX') and os.name=='posix','Unix transport')
    def test_real_mcp_content_and_correlations_reject_without_echo_or_mutation(self):
        with EphemeralHarness() as harness:
            client = harness.mcp('alpha','codex')
            secret = SECRETS['github_fine']
            params = {'subject':'Actual transport','claim':secret,'evidence':'Synthetic evidence.',
                      'source_handle':'fixture:actual','disclosure':['codex'],'idempotency_key':'actual-transport'}
            response = client.call_raw('memory_propose',params)
            self.assertEqual(response['result']['structuredContent']['error']['code'],'secret_rejected')
            self.assertNotIn(secret,canonical_json(response))
            request = {'jsonrpc':'2.0','id':secret,'method':'tools/call','params':{
                'name':'memory_propose','arguments':dict(params,claim='Harmless claim.'),'_meta':client._meta()}}
            client.process.stdin.write(canonical_json(request)+'\n'); client.process.stdin.flush()
            response = json.loads(client.process.stdout.readline())
            self.assertIsNone(response['id'])
            self.assertEqual(response['error']['code'],-32600)
            self.assertNotIn(secret,canonical_json(response))
            self.assertIn('status',client.call('memory_status',{}))
            scoped = load_capability(Path(harness.projects['alpha']['capabilities']['codex']))
            raw = {'id':secret,'method':'propose','auth':{'token':scoped['token']},
                   'params':dict(params, claim='Harmless claim.')}
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                sock.settimeout(3); sock.connect(str(harness.control.socket_path))
                sock.sendall((canonical_json(raw)+'\n').encode())
                response = json.loads(sock.recv(8192))
            self.assertEqual(response['error']['code'],'invalid_request')
            self.assertIsNone(response['id'])
            self.assertNotIn(secret,canonical_json(response))
            client.process.stdin.close(); self.assertEqual(client.process.wait(timeout=3),0)
            self.assertEqual(client.process.stderr.read(),'')
            connection = sqlite3.connect(str(harness.data_dir/'continuum.db'))
            try:
                self.assertEqual(connection.execute('SELECT count(*) FROM proposals').fetchone()[0],0)
            finally:
                connection.close()
            for path in harness.data_dir.iterdir():
                if path.is_file():
                    self.assertNotIn(secret.encode(),path.read_bytes(),path.name)


if __name__ == '__main__':
    unittest.main()
