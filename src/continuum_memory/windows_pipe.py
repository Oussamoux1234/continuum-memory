"""Peer-verified Windows named-pipe primitives used by the bounded native runtime.

This provides one bounded connection; windows_runtime owns the multi-client pool.
It authenticates the local process account, never human presence or an agent.
"""

import ctypes
import hashlib
import math
import os
import time
from contextlib import contextmanager

from .errors import MemoryError
from .security import MAX_FRAME_BYTES
from .windows_boundary import (
    BOOL, DWORD, HANDLE, LPWSTR, POINTER, GENERIC_READ, GENERIC_WRITE,
    INVALID_HANDLE, WindowsBoundary,
)

OVERLAPPED_FLAG = 0x40000000
FIRST_INSTANCE = 0x00080000
REJECT_REMOTE_CLIENTS = 0x8
SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_IDENTIFICATION = 0x00010000
HELLO = b"continuum-pipe-v1\n"
ACK = b"continuum-pipe-ok-v1\n"
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
ERROR_IO_PENDING = 997
ERROR_PIPE_CONNECTED = 535
CANCEL_GRACE_MS = 1000
FATAL_CANCEL_EXIT = 74
FATAL_REVERT_EXIT = 75
IDLE_CONNECT_POLL_MS = 250


class _Overlapped(ctypes.Structure):
    _fields_ = [("internal", ctypes.c_size_t), ("internal_high", ctypes.c_size_t),
                ("offset", DWORD), ("offset_high", DWORD), ("event", HANDLE)]


def _error(code="pipe_unavailable"):
    return MemoryError(code, "The local Windows pipe operation failed closed.")


def _deadline(seconds):
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 0 < seconds <= 10:
        raise _error("invalid_request")
    return time.monotonic() + seconds


def _remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise _error("pipe_timeout")
    return max(1, math.ceil(value * 1000))


def pipe_name(binding, sid):
    """Use an opaque, nonsecret 32-byte vault binding; no paths/capabilities in IPC names."""
    if not isinstance(binding, bytes) or len(binding) != 32 or not isinstance(sid, str):
        raise _error("invalid_request")
    digest = hashlib.sha256(sid.encode("ascii") + b"\0" + binding).hexdigest()
    return "\\\\.\\pipe\\continuum-memory-v1-" + digest


class _PipeAPI(WindowsBoundary):
    def _process_sid(self):
        self.require_process_context()
        return super()._process_sid()

    def _bind(self):
        super()._bind()
        signatures = (
            (self.kernel, "CreateNamedPipeW", HANDLE,
             [LPWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, POINTER]),
            (self.kernel, "ConnectNamedPipe", BOOL, [HANDLE, POINTER]),
            (self.kernel, "DisconnectNamedPipe", BOOL, [HANDLE]),
            (self.kernel, "CreateEventW", HANDLE, [POINTER, BOOL, BOOL, LPWSTR]),
            (self.kernel, "WaitForSingleObject", DWORD, [HANDLE, DWORD]),
            (self.kernel, "GetOverlappedResult", BOOL, [HANDLE, POINTER, POINTER, BOOL]),
            (self.kernel, "CancelIoEx", BOOL, [HANDLE, POINTER]),
            (self.kernel, "GetNamedPipeServerProcessId", BOOL, [HANDLE, POINTER]),
            (self.kernel, "GetNamedPipeClientProcessId", BOOL, [HANDLE, POINTER]),
            (self.kernel, "OpenProcess", HANDLE, [DWORD, BOOL, DWORD]),
            (self.kernel, "GetProcessTimes", BOOL, [HANDLE, POINTER, POINTER, POINTER, POINTER]),
            (self.kernel, "GetCurrentThread", HANDLE, []),
            (self.security, "ImpersonateNamedPipeClient", BOOL, [HANDLE]),
            (self.security, "OpenThreadToken", BOOL, [HANDLE, DWORD, BOOL, POINTER]),
            (self.security, "RevertToSelf", BOOL, []),
        )
        for library, name, result, arguments in signatures:
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments

    def require_process_context(self):
        token = HANDLE()
        if self.security.OpenThreadToken(self.kernel.GetCurrentThread(), 8, True, ctypes.byref(token)):
            self._close(token)
            raise _error("pipe_impersonated_context")
        # Never confuse inaccessible/anonymous/failed token queries with absence.
        if ctypes.get_last_error() != 1008:  # ERROR_NO_TOKEN
            raise _error("pipe_identity_unavailable")

    def token_sid(self, token):
        size = DWORD()
        self.security.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 0 < size.value <= 65536:
            raise _error("pipe_identity_unavailable")
        data = ctypes.create_string_buffer(size.value)
        if not self.security.GetTokenInformation(token, 1, data, size, ctypes.byref(size)):
            raise _error("pipe_identity_unavailable")
        return self._sid_string(POINTER.from_buffer(data).value)

    def identify_client(self, pipe):
        self.require_process_context()
        # The last message was the fixed nonsecret HELLO. Static identification
        # SQOS binds this token to the pipe client, not a potentially reused PID.
        if not self.security.ImpersonateNamedPipeClient(pipe):
            raise _error("pipe_identity_unavailable")
        token = HANDLE()
        try:
            if not self.security.OpenThreadToken(self.kernel.GetCurrentThread(), 8, True, ctypes.byref(token)):
                raise _error("pipe_identity_unavailable")
            level, size = DWORD(), DWORD()
            if not self.security.GetTokenInformation(token, 9, ctypes.byref(level), ctypes.sizeof(level), ctypes.byref(size)):
                raise _error("pipe_identity_unavailable")
            if level.value != 1 or self.token_sid(token) != self.sid:
                raise _error("unsafe_owner")
        finally:
            # Never return to a caller in a borrowed/uncertain security context.
            reverted = self.security.RevertToSelf()
            if not reverted:
                os._exit(FATAL_REVERT_EXIT)
            if token:
                self._close(token)

    def cancel_and_drain(self, pipe, operation):
        # Cancellation is a request, not completion. Keep OVERLAPPED and its
        # buffer alive until signaled; fail-stop if the kernel won't complete.
        self.kernel.CancelIoEx(pipe, ctypes.byref(operation))
        if self.kernel.WaitForSingleObject(operation.event, CANCEL_GRACE_MS) != WAIT_OBJECT_0:
            os._exit(FATAL_CANCEL_EXIT)
        transferred = DWORD()
        if (not self.kernel.GetOverlappedResult(pipe, ctypes.byref(operation), ctypes.byref(transferred), False)
                and ctypes.get_last_error() == 996):  # ERROR_IO_INCOMPLETE contradicts completion.
            os._exit(FATAL_CANCEL_EXIT)

    def operation(self, pipe, kind, deadline, data=None, size=0, stopping=None):
        idle_connect = stopping is not None
        if idle_connect:
            if kind != "connect":
                raise _error("invalid_request")
            if stopping.is_set():
                raise _error("pipe_stopping")
        else:
            _remaining(deadline)
        event = self.kernel.CreateEventW(None, True, False, None)
        if not event:
            raise _error()
        operation = _Overlapped(event=event)
        pending = False
        buffer = ctypes.create_string_buffer(data) if data is not None else ctypes.create_string_buffer(size)
        transferred = DWORD()
        try:
            # Set before the ctypes call: an asynchronous Python exception just
            # after native submission must not free an outstanding I/O buffer.
            pending = True
            if kind == "connect":
                succeeded = self.kernel.ConnectNamedPipe(pipe, ctypes.byref(operation))
            elif kind == "read":
                succeeded = self.kernel.ReadFile(pipe, buffer, size, None, ctypes.byref(operation))
            else:
                succeeded = self.kernel.WriteFile(pipe, buffer, len(data), None, ctypes.byref(operation))
            error = 0 if succeeded else ctypes.get_last_error()
            if kind == "connect" and error == ERROR_PIPE_CONNECTED:
                pending = False
                return b""
            if not succeeded and error != ERROR_IO_PENDING:
                pending = False
                raise _error()
            pending = not bool(succeeded)
            if pending:
                while True:
                    if idle_connect and stopping.is_set():
                        raise _error("pipe_stopping")
                    wait = self.kernel.WaitForSingleObject(
                        event, IDLE_CONNECT_POLL_MS if idle_connect else _remaining(deadline))
                    if wait == WAIT_OBJECT_0:
                        break
                    if wait == WAIT_TIMEOUT and idle_connect:
                        # Keep this same native operation/event alive. Cancelling
                        # at every idle poll can disconnect a just-arriving peer
                        # between its open and identity/hello validation.
                        continue
                    raise _error("pipe_timeout" if wait == WAIT_TIMEOUT else "pipe_unavailable")
            if not self.kernel.GetOverlappedResult(pipe, ctypes.byref(operation), ctypes.byref(transferred), False):
                pending = ctypes.get_last_error() == 996
                raise _error()
            pending = False
            if not idle_connect:
                _remaining(deadline)
            if kind == "read":
                return buffer.raw[:transferred.value]
            return transferred.value
        finally:
            if pending:
                self.cancel_and_drain(pipe, operation)
            self._close(event)


class _Peer:
    """Hold an actual process object, its token and creation identity through I/O."""

    def __init__(self, api, pipe, server_side):
        self.api, self.pipe = api, pipe
        self.pid_function = api.kernel.GetNamedPipeClientProcessId if server_side else api.kernel.GetNamedPipeServerProcessId
        self.process, self.token = None, HANDLE()
        try:
            self.pid = self._pid()
            self.process = api.kernel.OpenProcess(0x00101000, False, self.pid)  # SYNCHRONIZE | QUERY_LIMITED_INFORMATION
            if not self.process or not api.security.OpenProcessToken(self.process, 8, ctypes.byref(self.token)):
                raise _error("pipe_identity_unavailable")
            self.created = self._created()
            self.check()
        except BaseException:
            self.close()
            raise

    def _pid(self):
        pid = DWORD()
        if not self.pid_function(self.pipe, ctypes.byref(pid)) or not pid.value:
            raise _error("pipe_identity_unavailable")
        return pid.value

    def _created(self):
        created, exited, kernel, user = (ctypes.c_uint64() for _ in range(4))
        if not self.api.kernel.GetProcessTimes(self.process, ctypes.byref(created), ctypes.byref(exited),
                                             ctypes.byref(kernel), ctypes.byref(user)):
            raise _error("pipe_identity_unavailable")
        return created.value

    def check(self):
        if (self._pid() != self.pid or self._created() != self.created
                or self.api.kernel.WaitForSingleObject(self.process, 0) != WAIT_TIMEOUT):
            raise _error("pipe_identity_unavailable")
        if self.api.token_sid(self.token) != self.api.sid:
            raise _error("unsafe_owner")

    def close(self):
        try:
            if self.token:
                token, self.token = self.token, HANDLE()
                self.api._close(token)
        finally:
            if self.process:
                process, self.process = self.process, None
                self.api._close(process)


class PipeConnection:
    def __init__(self, api, handle, peer, deadline):
        self.api, self.handle, self.peer, self.deadline = api, handle, peer, deadline

    def send(self, frame):
        self.api.require_process_context()
        if (not isinstance(frame, bytes) or not 0 < len(frame) <= MAX_FRAME_BYTES
                or frame.find(b"\n") != len(frame) - 1):
            raise _error("invalid_frame")
        offset = 0
        while offset < len(frame):
            self.peer.check()
            written = self.api.operation(self.handle, "write", self.deadline, data=frame[offset:offset + 8192])
            if not written:
                raise _error()
            offset += written
        self.peer.check()

    def receive(self, maximum=MAX_FRAME_BYTES):
        self.api.require_process_context()
        if type(maximum) is not int or not 1 <= maximum <= MAX_FRAME_BYTES:
            raise _error("invalid_frame")
        result = bytearray()
        while len(result) < maximum:
            self.peer.check()
            chunk = self.api.operation(self.handle, "read", self.deadline, size=min(8192, maximum - len(result)))
            if not chunk:
                raise _error("invalid_frame")
            result.extend(chunk)
            newline = result.find(b"\n")
            if newline >= 0:
                if newline != len(result) - 1:
                    raise _error("invalid_frame")
                self.peer.check()
                return bytes(result)
        raise _error("invalid_frame")


class PipeServer:
    """A reusable instance; followers require a held first-instance anchor."""

    def __init__(self, binding, max_instances=1, anchor=None):
        self.api = _PipeAPI()
        self.name = pipe_name(binding, self.api.sid)
        self.handle = None
        if type(max_instances) is not int or not 1 <= max_instances <= 16:
            raise _error("invalid_request")
        self.max_instances = max_instances
        if anchor is not None:
            if (not isinstance(anchor, PipeServer) or anchor.handle is None
                    or anchor.name != self.name or anchor.max_instances != max_instances):
                raise _error("pipe_endpoint_occupied")
            anchor.api._private_acl(anchor.handle)
        with self.api._attributes() as attributes:
            handle = self.api.kernel.CreateNamedPipeW(
                self.name, 3 | OVERLAPPED_FLAG | (FIRST_INSTANCE if anchor is None else 0), REJECT_REMOTE_CLIENTS,
                max_instances, 8192, 8192, 0, ctypes.byref(attributes),
            )
        if handle in (None, INVALID_HANDLE):
            raise _error("pipe_endpoint_occupied")
        self.handle = handle
        try:
            self.api._private_acl(handle)
        except BaseException:
            self.close()
            raise

    @contextmanager
    def accept(self, timeout=5.0, connect_timeout=None, stopping=None):
        self.api.require_process_context()
        if stopping is not None and connect_timeout is not None:
            raise _error("invalid_request")
        deadline = _deadline(timeout)
        peer = None
        try:
            self.api.operation(self.handle, "connect", _deadline(connect_timeout) if connect_timeout is not None else deadline,
                               stopping=stopping)
            if connect_timeout is not None or stopping is not None:
                # Time spent waiting for any peer must not consume a newly
                # connected peer's handshake/frame budget in a long-lived pool.
                deadline = _deadline(timeout)
            peer = _Peer(self.api, self.handle, True)
            connection = PipeConnection(self.api, self.handle, peer, deadline)
            if connection.receive(len(HELLO)) != HELLO:
                raise _error("invalid_frame")
            self.api.identify_client(self.handle)
            peer.check()
            connection.send(ACK)
            yield connection
        finally:
            try:
                if peer is not None:
                    peer.close()
            finally:
                if self.handle is not None:
                    self.api.kernel.DisconnectNamedPipe(self.handle)

    def close(self):
        if self.handle is not None:
            handle, self.handle = self.handle, None
            self.api._close(handle)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


@contextmanager
def connect(binding, timeout=5.0):
    deadline = _deadline(timeout)
    api = _PipeAPI()
    handle = api.kernel.CreateFileW(
        pipe_name(binding, api.sid), GENERIC_READ | GENERIC_WRITE | 0x20000, 0, None, 3,
        OVERLAPPED_FLAG | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, None,
    )
    # No WaitNamedPipe / synchronous retry: a missing or busy endpoint is unavailable.
    if handle in (None, INVALID_HANDLE):
        raise _error()
    peer = None
    try:
        api._private_acl(handle)  # Object owner prevents the pre-OpenProcess PID-reuse ambiguity.
        peer = _Peer(api, handle, False)
        connection = PipeConnection(api, handle, peer, deadline)
        connection.send(HELLO)
        if connection.receive(len(ACK)) != ACK:
            raise _error("invalid_frame")
        yield connection
    finally:
        try:
            if peer is not None:
                peer.close()
        finally:
            api._close(handle)
