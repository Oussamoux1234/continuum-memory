"""Genuine two-account acceptance; invoked only by the disposable CI wrapper.

All vault material is generated here. The shared directory is coordination, not
a vault. This fixture neither provisions accounts nor changes production ACLs.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor


ROOT = Path(__file__).resolve().parents[1]
OPT_IN = "CONTINUUM_CI_FOREIGN_ACCOUNT_FIXTURE"
SID_PATTERN = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+\Z")
CURRENT_PHASE = "initial"


class AcceptanceFailure(RuntimeError):
    def __init__(self, stage, native_status=None):
        super().__init__(stage)
        self.stage, self.native_status = stage, native_status


def require(condition, stage):
    if not condition:
        raise AcceptanceFailure(stage)


def phase(name):
    global CURRENT_PHASE
    CURRENT_PHASE = name


def guard(mode, shared, owner_sid, foreign_sid):
    required = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows",
                "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_ARCH": "X64",
                OPT_IN: "approved-disposable-account-v1",
                "CONTINUUM_CI_OWNER_FIXTURE": "approved-process-only-v1"}
    require(os.name == "nt" and struct.calcsize("P") == 8
            and all(os.environ.get(key) == value for key, value in required.items()), "scope_environment")
    require(mode in ("owner", "foreign"), "scope_mode")
    require(owner_sid != foreign_sid and SID_PATTERN.fullmatch(owner_sid)
            and SID_PATTERN.fullmatch(foreign_sid), "scope_identity")
    require(Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve() == ROOT
            and Path.cwd().resolve() == ROOT, "scope_checkout")
    temporary = os.environ.get("RUNNER_TEMP")
    require(temporary and shared.parent.resolve() == Path(temporary).resolve()
            and re.fullmatch(r"continuum-foreign-[0-9a-f]{32}", shared.name), "scope_temporary")
    require(shared.is_dir() and not shared.is_symlink(), "scope_directory")


def publish(shared, name, value):
    temporary = shared / (name + ".pending")
    temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    temporary.replace(shared / name)


def await_report(shared, name, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        path = shared / name
        if path.is_file():
            data = path.read_bytes()
            require(len(data) <= 16384, "coordination_size")
            return json.loads(data)
        time.sleep(0.05)
    raise AcceptanceFailure("coordination_timeout")


def assert_denied(api, path, access, flags=0):
    from continuum_memory.windows_boundary import INVALID_HANDLE
    handle = api.kernel.CreateFileW(str(path), access, 7, None, 3, flags, None)
    if handle not in (None, INVALID_HANDLE):
        api._close(handle)
        raise AcceptanceFailure("foreign_access_admitted")
    status = ctypes.get_last_error()
    if status != 5:  # Missing file/pipe or failed execution is NOT denial evidence.
        raise AcceptanceFailure("foreign_denial_not_access_denied", status)


def owner_roundtrip(server, binding):
    from continuum_memory.windows_pipe import connect

    def echo():
        with server.accept() as connection:
            require(connection.receive() == b"synthetic-positive-control\n", "owner_server_payload")
            connection.send(b"synthetic-positive-control\n")

    with ThreadPoolExecutor(max_workers=1) as worker:
        result = worker.submit(echo)
        with connect(binding) as connection:
            connection.send(b"synthetic-positive-control\n")
            require(connection.receive() == b"synthetic-positive-control\n", "owner_client_payload")
        result.result(timeout=6)


def file_digests(files):
    from continuum_memory.windows_boundary import GENERIC_READ, WindowsBoundary
    boundary, digests = WindowsBoundary(), {}
    for name, path in files.items():
        # Synthetic databases exceed the public 64 KiB private-material limit.
        # Use the existing pinned native handle and bounded chunked reader; do
        # not weaken the production read_private contract or drop ACL checks.
        with boundary.open_private(path, access=GENERIC_READ) as handle:
            digests[name] = hashlib.sha256(boundary._read_handle(handle, 4 * 1024 * 1024)).digest()
    return digests


def owner(shared, owner_sid, foreign_sid):
    from continuum_memory.errors import MemoryError
    from continuum_memory.security import create_private_directory, read_private
    from continuum_memory.storage import Store, paths
    from continuum_memory.windows_boundary import WindowsBoundary
    from continuum_memory.windows_pipe import PipeServer, connect
    from fixtures.windows_test_owner import temporary_owner

    require(WindowsBoundary().sid == owner_sid, "owner_identity")
    phase("owner_token_fixture")
    with temporary_owner() as restoration:
        phase("owner_vault_bootstrap")
        vault = shared / "private-vault"
        create_private_directory(vault)
        manifest = Store.bootstrap(vault, [{"name": "Synthetic cross-account acceptance",
            "path_hint": "/fixture/foreign-account", "providers": ["codex"]}])
        phase("owner_store_open")
        store = Store(vault)
        try:
            store.connection.execute("INSERT INTO metadata VALUES ('foreign_fixture','synthetic')")
            store.connection.commit()
            mapped = paths(vault)
            files = {"database": mapped["db"], "audit_key": mapped["audit_key"],
                     "control_capability": mapped["control"], "ipc_binding": mapped["ipc_binding"],
                     "agent_capability": Path(manifest["projects"][0]["capabilities"]["codex"]),
                     "wal": Path(str(mapped["db"]) + "-wal"), "shm": Path(str(mapped["db"]) + "-shm")}
            require(all(path.is_file() for path in files.values()), "owner_files_exist")
            phase("owner_file_controls")
            before = file_digests(files)
            binding = read_private(mapped["ipc_binding"], 32)
            foreign_binding = secrets.token_bytes(32)
            with PipeServer(binding) as server:
                phase("owner_roundtrip_before")
                owner_roundtrip(server, binding)
                publish(shared, "owner-ready.json", {
                    "files": {name: str(path.relative_to(shared)) for name, path in files.items()},
                    "binding": binding.hex(), "foreign_binding": foreign_binding.hex(),
                    "positive_control": "synthetic-shared-control"})
                phase("owner_wait_foreign")
                report = await_report(shared, "foreign-ready.json")
                require(report == {"sid": foreign_sid, "standard_account": True,
                    "shared_control": True, "file_read_denials": len(files),
                    "file_write_denials": len(files), "directory_denied": True,
                    "owner_pipe_denied": True}, "foreign_report")
                phase("owner_reject_foreign_pipe")
                try:
                    with connect(foreign_binding):
                        raise AcceptanceFailure("foreign_owned_pipe_admitted")
                except MemoryError as error:
                    require(error.code == "unsafe_owner", "foreign_pipe_wrong_rejection")
                phase("owner_roundtrip_after")
                owner_roundtrip(server, binding)
                phase("owner_recovery_files")
                require(file_digests(files) == before, "owner_files_changed")
                phase("owner_recovery_audit")
                require(store.verify_audit()["status"] == "valid", "owner_audit_recovery")
                publish(shared, "owner-checked.json", {"foreign_owner_rejected": True})
                require(await_report(shared, "foreign-done.json") == {"completed": True}, "foreign_completion")
        finally:
            store.close()
    require(restoration["restored"] and restoration["parent_unchanged"], "owner_restoration")
    result = {"genuine_foreign_identity": True, "foreign_standard_account": True,
              "shared_execution_control": True, "file_read_denials": len(files),
              "file_write_denials": len(files), "directory_denied": True,
              "owner_pipe_access_denied": True, "foreign_pipe_owner_rejected": True,
              "owner_roundtrip_before_after": True, "private_bytes_unchanged": True,
              "audit_valid_after": True, "owner_restored": True, "parent_unchanged": True}
    publish(shared, "accepted.json", result)
    print(json.dumps({"windows_foreign_account_acceptance": result}), flush=True)


def foreign(shared, owner_sid, foreign_sid):
    from continuum_memory.windows_boundary import (
        BOOL, POINTER, INVALID_HANDLE, _SecurityAttributes, FILE_FLAG_BACKUP_SEMANTICS)
    from continuum_memory.windows_pipe import (
        _PipeAPI, FIRST_INSTANCE, OVERLAPPED_FLAG, REJECT_REMOTE_CLIENTS, pipe_name)

    api = _PipeAPI()
    phase("foreign_identity_control")
    require(api.sid == foreign_sid and api.sid != owner_sid, "foreign_identity")
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.IsUserAnAdmin.argtypes, shell.IsUserAnAdmin.restype = [], BOOL
    require(not shell.IsUserAnAdmin(), "foreign_admin_token")
    ready = await_report(shared, "owner-ready.json")
    phase("foreign_shared_control")
    require(ready["positive_control"] == "synthetic-shared-control", "shared_read_control")
    # This independently proves the new process ran and can write the shared
    # synthetic area. A launch error or inaccessible Python cannot pass.
    publish(shared, "foreign-control.json", {"positive_control": "synthetic-shared-control"})
    require(await_report(shared, "foreign-control.json") == {
        "positive_control": "synthetic-shared-control"}, "shared_write_control")
    phase("foreign_filesystem_denials")
    assert_denied(api, shared / "private-vault", 0x80000000, FILE_FLAG_BACKUP_SEMANTICS)
    files = ready["files"]
    require(set(files) == {"database", "audit_key", "control_capability", "ipc_binding",
                           "agent_capability", "wal", "shm"}, "file_inventory")
    for relative in files.values():
        path = shared / relative
        require(path.is_relative_to(shared / "private-vault"), "private_target")
        assert_denied(api, path, 0x80000000)
        assert_denied(api, path, 0x40000000)
    binding = bytes.fromhex(ready["binding"])
    phase("foreign_owner_pipe_denial")
    assert_denied(api, pipe_name(binding, owner_sid), 0xC0020000,
                  OVERLAPPED_FLAG | 0x00110000)
    # A distinct synthetic endpoint grants the owner read/write solely so its
    # real foreign OWNER is observable by production connect(). No production
    # pipe or vault ACL is broadened and no expected SID is replaced or mocked.
    phase("foreign_pipe_create")
    descriptor = POINTER()
    sddl = "O:%sD:P(A;;FA;;;%s)(A;;0x0012019f;;;%s)" % (foreign_sid, foreign_sid, owner_sid)
    require(api.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None), "foreign_pipe_descriptor")
    try:
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        handle = api.kernel.CreateNamedPipeW(
            pipe_name(bytes.fromhex(ready["foreign_binding"]), owner_sid),
            3 | OVERLAPPED_FLAG | FIRST_INSTANCE, REJECT_REMOTE_CLIENTS,
            1, 8192, 8192, 0, ctypes.byref(attributes))
    finally:
        api.kernel.LocalFree(descriptor)
    if handle in (None, INVALID_HANDLE):
        raise AcceptanceFailure("foreign_pipe_creation", ctypes.get_last_error())
    try:
        phase("foreign_wait_owner_check")
        publish(shared, "foreign-ready.json", {"sid": api.sid, "standard_account": True,
            "shared_control": True, "file_read_denials": len(files), "file_write_denials": len(files),
            "directory_denied": True, "owner_pipe_denied": True})
        require(await_report(shared, "owner-checked.json") == {
            "foreign_owner_rejected": True}, "owner_pipe_rejection_control")
    finally:
        api._close(handle)
    publish(shared, "foreign-done.json", {"completed": True})


def main():
    try:
        require(len(sys.argv) == 5, "arguments")
        mode, directory, owner_sid, foreign_sid = sys.argv[1:]
        shared = Path(directory)
        guard(mode, shared, owner_sid, foreign_sid)
        sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
        (owner if mode == "owner" else foreign)(shared, owner_sid, foreign_sid)
        return 0
    except BaseException as error:
        detail = {"stage": error.stage if isinstance(error, AcceptanceFailure) else CURRENT_PHASE}
        code = getattr(error, "code", None)
        if isinstance(code, str) and re.fullmatch(r"[a-z_]+", code):
            detail["error_code"] = code
        if isinstance(error, AcceptanceFailure) and error.native_status is not None:
            detail["native_status"] = error.native_status
        # Native exception messages can include paths. Credentials are never
        # received here; even synthetic capabilities and keys are not printed.
        print(json.dumps({"windows_foreign_account_error": detail}), file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
