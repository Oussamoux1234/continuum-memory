"""Explicitly approved disposable CI-process fixture, never production setup.

Changes only the current primary token's default owner to its existing TokenUser
SID, restoring the previous owner before return. No account, group, privilege,
host policy, default DACL, impersonation or parent-token changes are performed.
Environment guards prevent accidental invocation; they are not authentication.
The workflow's reviewed opt-in is the authorization. This module is not installed
in the runtime wheel and accepts no arbitrary command or SID.
"""

import ctypes
import json
import os
import struct
import subprocess
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OPT_IN = "CONTINUUM_CI_OWNER_FIXTURE"
FATAL_RESTORE_EXIT = 79


class FixtureFailure(RuntimeError):
    """Only reviewed constant phase labels and optional native numbers are logged."""
    def __init__(self, stage, native_status=None):
        super().__init__(stage)
        self.stage, self.native_status = stage, native_status


def _guard_scope():
    required = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows",
                "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_ARCH": "X64",
                OPT_IN: "approved-process-only-v1"}
    if os.name != "nt" or struct.calcsize("P") != 8 or any(os.environ.get(k) != v for k, v in required.items()):
        raise FixtureFailure("scope_environment")
    workspace = os.environ.get("GITHUB_WORKSPACE")
    if not workspace or Path(workspace).resolve() != ROOT or Path.cwd().resolve() != ROOT:
        raise FixtureFailure("scope_checkout")


class _OwnerAPI:
    def __init__(self):
        from continuum_memory.windows_pipe import _PipeAPI
        from continuum_memory.windows_boundary import BOOL, DWORD, HANDLE, POINTER
        self.api = _PipeAPI()  # Also refuses an existing impersonation context.
        self.HANDLE, self.DWORD, self.POINTER = HANDLE, DWORD, POINTER
        setter = self.api.security.SetTokenInformation
        setter.argtypes, setter.restype = [HANDLE, DWORD, POINTER, DWORD], BOOL
        self.handles = []

    def close(self):
        with ExitStack() as cleanup:
            for handle in self.handles:
                cleanup.callback(self.api._close, handle)
            self.handles.clear()

    def _token(self, process, access):
        token = self.HANDLE()
        if not self.api.security.OpenProcessToken(process, access, ctypes.byref(token)):
            raise FixtureFailure("token_open", ctypes.get_last_error())
        self.handles.append(token)
        return token

    def info(self, token, information_class):
        size = self.DWORD()
        self.api.security.GetTokenInformation(token, information_class, None, 0, ctypes.byref(size))
        if not ctypes.sizeof(self.POINTER) <= size.value <= 65536:
            raise FixtureFailure("token_query_size", ctypes.get_last_error())
        result = ctypes.create_string_buffer(size.value)
        if not self.api.security.GetTokenInformation(token, information_class, result, size, ctypes.byref(size)):
            raise FixtureFailure("token_query", ctypes.get_last_error())
        return result

    def sid(self, data):
        return self.api._sid_string(self.POINTER.from_buffer(data).value)

    def owner(self, token):
        return self.sid(self.info(token, 4))

    def open(self):
        self.current = self._token(self.api.kernel.GetCurrentProcess(), 0x88)  # QUERY | ADJUST_DEFAULT only.
        process = self.api.kernel.OpenProcess(0x1000, False, os.getppid())  # QUERY_LIMITED_INFORMATION only.
        if not process:
            raise FixtureFailure("parent_open", ctypes.get_last_error())
        self.handles.append(process)
        self.parent = self._token(process, 0x8)
        # TOKEN_STATISTICS.TokenId is its first LUID (8 bytes), identifying the
        # token object, not the logon session. Never alter a shared parent token.
        current_id = self.info(self.current, 10).raw[:8]
        parent_id = self.info(self.parent, 10).raw[:8]
        if current_id == parent_id:
            raise FixtureFailure("shared_parent_token")
        self.user = self.info(self.current, 1)
        self.original = self.info(self.current, 4)
        self.parent_owner = self.owner(self.parent)
        return self

    def set_owner(self, data):
        # Pointer targets only retained TokenUser/original TokenOwner information
        # from this exact token. Neither a caller-supplied SID nor account lookup.
        value = self.POINTER(self.POINTER.from_buffer(data).value)
        if not self.api.security.SetTokenInformation(self.current, 4, ctypes.byref(value), ctypes.sizeof(value)):
            raise FixtureFailure("token_owner_set", ctypes.get_last_error())


@contextmanager
def temporary_owner():
    _guard_scope()
    api = _OwnerAPI()
    evidence = {"changed": False, "restored": False, "parent_unchanged": False}
    try:
        api.open()
        original, desired = api.sid(api.original), api.sid(api.user)
        evidence["changed"] = original != desired
        # Restore even if asynchronous interruption occurs immediately after the
        # native update, before Python has observed its return value.
        try:
            api.set_owner(api.user)
            if api.owner(api.current) != desired or api.owner(api.parent) != api.parent_owner:
                raise FixtureFailure("owner_readback")
            yield evidence
        finally:
            try:
                api.set_owner(api.original)
                evidence["restored"] = api.owner(api.current) == original
                evidence["parent_unchanged"] = api.owner(api.parent) == api.parent_owner
                if not evidence["restored"] or not evidence["parent_unchanged"]:
                    raise FixtureFailure("owner_restore_readback")
            except BaseException:
                # Do not proceed with verification or report success in an
                # uncertain token context. This is fixture-only, not recovery.
                print('{"ci_owner_fixture_error":{"stage":"fatal_restore"}}', file=sys.stderr, flush=True)
                os._exit(FATAL_RESTORE_EXIT)
    finally:
        api.close()


def _require_production_behavior(boundary, compatible):
    from continuum_memory.errors import MemoryError
    try:
        boundary.require_creation_owner()
    except MemoryError as error:
        if compatible or error.code != "unsupported_token_owner":
            raise
    else:
        if not compatible:
            raise FixtureFailure("production_mismatch_admitted")


def preflight():
    """Real current/child token, inherited file owner, and both restoration paths."""
    _guard_scope()
    from continuum_memory.windows_boundary import WindowsBoundary
    boundary = WindowsBoundary()
    original = boundary._process_sid(4)
    compatible = original == boundary.sid
    _require_production_behavior(boundary, compatible)
    with temporary_owner() as success:
        boundary.require_creation_owner()
        with tempfile.TemporaryDirectory(prefix="continuum-ci-owner-") as temporary:
            private = Path(temporary) / "synthetic"
            boundary.create_directory(private)
            child_file = private / "child-created"
            program = (
                "import json,sys; from pathlib import Path; "
                "from continuum_memory.windows_boundary import WindowsBoundary; "
                "b=WindowsBoundary(); b.require_creation_owner(); "
                "Path(sys.argv[1]).write_bytes(b'synthetic owner fixture'); "
                "b.inspect(Path(sys.argv[1])); "
                "print(json.dumps({'owner_matches':b._process_sid(4)==b.sid}))")
            result = subprocess.run([sys.executable, "-c", program, str(child_file)],
                env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
                capture_output=True, timeout=15, check=False)
            if result.returncode or json.loads(result.stdout) != {"owner_matches": True}:
                raise FixtureFailure("child_owner_inheritance")
            if boundary.read(child_file) != b"synthetic owner fixture":
                raise FixtureFailure("child_object_owner")
    if boundary._process_sid(4) != original:
        raise FixtureFailure("success_owner_restore")
    _require_production_behavior(boundary, compatible)
    class DeliberateFailure(Exception):
        pass
    try:
        with temporary_owner() as failed:
            boundary.require_creation_owner()
            raise DeliberateFailure()
    except DeliberateFailure:
        pass
    if boundary._process_sid(4) != original:
        raise FixtureFailure("exception_owner_restore")
    _require_production_behavior(boundary, compatible)
    return {"original_owner_compatible": compatible, "changed": success["changed"],
            "restored_after_success": success["restored"], "restored_after_exception": failed["restored"],
            "parent_unchanged": success["parent_unchanged"] and failed["parent_unchanged"],
            "child_owner_matches": True}


def main():
    if len(sys.argv) != 1:
        print("CI owner fixture accepts no arguments", file=sys.stderr)
        return 2
    try:
        _guard_scope()
        # Imports stay source-checkout-only; nothing is added to production.
        sys.path.insert(0, str(ROOT / "src"))
        print(json.dumps({"ci_process_owner_preflight": preflight()}), flush=True)
        with temporary_owner() as evidence:
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / "verify.py")],
                                    cwd=ROOT, timeout=20 * 60, check=False)
        print(json.dumps({"ci_process_owner_restoration": evidence}), flush=True)
        return result.returncode
    except Exception as error:
        details = {"stage": error.stage if isinstance(error, FixtureFailure) else "unexpected_fixture_failure"}
        if isinstance(error, FixtureFailure) and error.native_status is not None:
            details["native_status"] = error.native_status
        print(json.dumps({"ci_owner_fixture_error": details}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
