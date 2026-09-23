"""Real native pipes/processes; deterministic fatal-fault fixtures are labeled."""

import ctypes
import os
import secrets
import subprocess
import sys
import time
import unittest
from pathlib import Path

from continuum_memory.errors import MemoryError
from continuum_memory.windows_boundary import BOOL, DWORD, HANDLE, POINTER, _SecurityAttributes
from continuum_memory.windows_pipe import (
    FATAL_CANCEL_EXIT, FATAL_REVERT_EXIT, FIRST_INSTANCE, OVERLAPPED_FLAG,
    REJECT_REMOTE_CLIENTS, PipeServer, _Overlapped, _PipeAPI, _Peer, connect, pipe_name,
)


ROOT = Path(__file__).resolve().parents[1]


class PipeInputTest(unittest.TestCase):
    def test_name_uses_only_opaque_scoped_digest(self):
        binding = b"a" * 32
        name = pipe_name(binding, "S-1-5-21-123")
        self.assertRegex(name, r"^\\\\\.\\pipe\\continuum-memory-v1-[a-f0-9]{64}$")
        self.assertNotIn("S-1-5", name)
        self.assertNotEqual(name, pipe_name(binding, "S-1-5-21-456"))
        self.assertNotEqual(name, pipe_name(b"b" * 32, "S-1-5-21-123"))
        for invalid in (None, "secret", b"short"):
            with self.assertRaises(MemoryError):
                pipe_name(invalid, "S-1-5-21-123")


@unittest.skipUnless(os.name == "nt", "Native Windows pipe evidence requires Windows")
class NativePipeTest(unittest.TestCase):
    def setUp(self):
        self.binding = secrets.token_bytes(32)
        self.environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"))

    def stop(self, child):
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)

    def child(self, mode, binding=None):
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--pipe-child", mode, (binding or self.binding).hex()],
            env=self.environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.addCleanup(self.stop, process)
        return process

    def signal(self, child, expected):
        # Read process stdout with native PeekNamedPipe, never an unbounded
        # synchronous readline or a background thread left behind on timeout.
        import msvcrt
        api = _PipeAPI()
        peek = api.kernel.PeekNamedPipe
        peek.argtypes, peek.restype = [HANDLE, POINTER, DWORD, POINTER, POINTER, POINTER], BOOL
        handle = msvcrt.get_osfhandle(child.stdout.fileno())
        deadline = time.monotonic() + 5
        data = bytearray()
        while time.monotonic() < deadline:
            available = DWORD()
            if not peek(handle, None, 0, None, ctypes.byref(available), None):
                break
            if available.value:
                data.extend(os.read(child.stdout.fileno(), 1))
                if data.endswith(b"\n"):
                    self.assertEqual(bytes(data), expected + b"\n")
                    return
            else:
                time.sleep(0.01)
        self.fail("Native fixture did not reach its bounded barrier")

    def finish(self, child):
        output, error = child.communicate(input=b"stop\n", timeout=5)
        self.assertEqual(child.returncode, 0, error)
        self.assertEqual(error, b"")
        return output

    def test_native_roundtrip_maximum_frame_and_overlapped_abi(self):
        self.assertEqual(ctypes.sizeof(_Overlapped), 32)
        child = self.child("echo")
        self.signal(child, b"ready")
        payload = b"x" * 65535 + b"\n"
        with connect(self.binding) as connection:
            connection.send(payload)
            self.assertEqual(connection.receive(), payload)
        self.finish(child)

    def test_first_instance_rejects_squatting_and_closing_releases_name(self):
        with PipeServer(self.binding):
            with self.assertRaises(MemoryError) as error:
                PipeServer(self.binding)
            self.assertEqual(error.exception.code, "pipe_endpoint_occupied")
        with PipeServer(self.binding):
            pass

    def test_actual_pipe_wrong_owner_rejected_before_hello(self):
        # Native Administrators-owned object, same process account. This proves
        # pipe OWNER validation, NOT a second-account peer-process fixture.
        child = self.child("foreign-owner")
        self.signal(child, b"ready")
        with self.assertRaises(MemoryError) as error:
            with connect(self.binding):
                self.fail("Wrong-owner endpoint was accepted")
        self.assertEqual(error.exception.code, "unsafe_owner")
        self.finish(child)

    def test_native_peer_token_is_compared_not_pid_only(self):
        child = self.child("echo")
        self.signal(child, b"ready")
        with connect(self.binding) as connection:
            api = _PipeAPI()
            api.sid = "S-1-5-32-544"  # Deliberate expected-identity mismatch.
            with self.assertRaises(MemoryError) as error:
                _Peer(api, connection.handle, False)
            self.assertEqual(error.exception.code, "unsafe_owner")
            connection.send(b"ok\n")
            self.assertEqual(connection.receive(), b"ok\n")
        self.finish(child)

    def test_connect_read_and_write_deadlines_cancel_cleanly(self):
        with PipeServer(self.binding) as server:
            started = time.monotonic()
            with self.assertRaises(MemoryError) as error:
                with server.accept(0.15):
                    self.fail("Unexpected connection")
            self.assertEqual(error.exception.code, "pipe_timeout")
            self.assertLess(time.monotonic() - started, 1.5)
        for operation in ("read", "write"):
            with self.subTest(operation=operation), PipeServer(self.binding) as server:
                child = self.child("idle-client")
                with server.accept(0.4) as connection:
                    self.signal(child, b"connected")
                    started = time.monotonic()
                    with self.assertRaises(MemoryError) as error:
                        if operation == "read":
                            connection.receive()
                        else:
                            connection.send(b"x" * 65535 + b"\n")
                    self.assertEqual(error.exception.code, "pipe_timeout")
                    self.assertLess(time.monotonic() - started, 1.5)
                self.finish(child)

    def test_client_handshake_deadline_and_missing_endpoint(self):
        with self.assertRaises(MemoryError):
            with connect(self.binding, 0.15):
                self.fail("Missing endpoint accepted")
        with PipeServer(self.binding):
            started = time.monotonic()
            with self.assertRaises(MemoryError) as error:
                with connect(self.binding, 0.15):
                    self.fail("Silent server accepted")
            self.assertEqual(error.exception.code, "pipe_timeout")
            self.assertLess(time.monotonic() - started, 1.5)

    def test_oversize_truncation_and_multiple_frames_rejected(self):
        for mode in ("oversize-client", "multiple-client", "truncated-client"):
            with self.subTest(mode=mode), PipeServer(self.binding) as server:
                child = self.child(mode)
                with server.accept() as connection:
                    with self.assertRaises(MemoryError):
                        connection.receive()
                output, error = child.communicate(input=b"stop\n", timeout=5)
                self.assertEqual(child.returncode, 0, error)

    def test_peer_exit_is_detected_without_following_replacement_pid(self):
        with PipeServer(self.binding) as server:
            child = self.child("idle-client")
            with server.accept() as connection:
                self.signal(child, b"connected")
                child.kill()
                child.communicate(timeout=5)
                with self.assertRaises(MemoryError) as error:
                    connection.send(b"must-not-be-sent\n")
                self.assertEqual(error.exception.code, "pipe_identity_unavailable")

    def test_fatal_fault_fixtures_terminate_not_hang(self):
        # These are deliberately injected API failures, not a real kernel
        # cancellation failure or observed OS impersonation cleanup failure.
        for mode, expected in (("fatal-cancel", FATAL_CANCEL_EXIT), ("fatal-revert", FATAL_REVERT_EXIT)):
            child = self.child(mode)
            output, error = child.communicate(timeout=5)
            self.assertEqual(child.returncode, expected)
            self.assertEqual(output + error, b"")


def child_main():
    # Fixture control stdout has an explicit LF protocol; do not let Windows
    # text translation turn these markers into CRLF. Actual pipe frames are bytes.
    sys.stdout.reconfigure(newline="\n")
    mode, binding = sys.argv[2], bytes.fromhex(sys.argv[3])
    if mode.startswith("fatal-"):
        api = _PipeAPI()
        if mode == "fatal-cancel":
            api.kernel.CancelIoEx = lambda *_args: True
            api.kernel.WaitForSingleObject = lambda *_args: 258
            api.cancel_and_drain(None, _Overlapped())
        else:
            api.security.ImpersonateNamedPipeClient = lambda *_args: True
            api.security.OpenThreadToken = lambda *_args: False
            api.security.RevertToSelf = lambda: False
            api.identify_client(None)
        raise RuntimeError("Injected fatal branch did not terminate")
    if mode == "foreign-owner":
        api = _PipeAPI()
        descriptor = POINTER()
        sddl = "O:BAD:P(A;;FA;;;%s)" % api.sid
        if not api.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise RuntimeError("Synthetic foreign-owner descriptor failed")
        try:
            attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
            handle = api.kernel.CreateNamedPipeW(pipe_name(binding, api.sid), 3 | OVERLAPPED_FLAG | FIRST_INSTANCE,
                                                REJECT_REMOTE_CLIENTS, 1, 8192, 8192, 0, ctypes.byref(attributes))
        finally:
            api.kernel.LocalFree(descriptor)
        if handle in (None, ctypes.c_void_p(-1).value):
            raise RuntimeError("Synthetic foreign-owner pipe requires fixture privilege")
        try:
            print("ready", flush=True)
            sys.stdin.readline()
        finally:
            api._close(handle)
        return
    if mode == "echo":
        with PipeServer(binding) as server:
            print("ready", flush=True)
            with server.accept() as connection:
                connection.send(connection.receive())
                sys.stdin.readline()  # Keep authenticated process alive through client delivery.
        return
    with connect(binding) as connection:
        if mode == "idle-client":
            print("connected", flush=True)
            sys.stdin.readline()
        elif mode == "truncated-client":
            connection.api.operation(connection.handle, "write", connection.deadline, data=b"partial")
            return
        else:
            payload = b"x" * 65536 if mode == "oversize-client" else b"first\nsecond\n"
            for offset in range(0, len(payload), 8192):
                connection.api.operation(connection.handle, "write", connection.deadline, data=payload[offset:offset + 8192])
            sys.stdin.readline()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--pipe-child":
        child_main()
    else:
        unittest.main()
