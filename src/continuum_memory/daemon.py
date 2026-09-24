"""Owner-only local daemon with platform I/O and serialized application dispatch."""

import os
import selectors
import signal
import socket
import stat
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable, Dict

from .daemon_lock import DaemonLock, same_inode
from .errors import MemoryError
from .kernel import Kernel
from .peer import verify_peer_owner
from .security import (
    ContentSafeArgumentParser,
    MAX_FRAME_BYTES,
    absolute_path,
    canonical_json,
    ensure_private_directory,
    ensure_private_socket,
    require_keys,
)
from .storage import Store, paths
from .transport import (
    CHUNK_BYTES,
    MAX_CONNECTIONS,
    READ_TIMEOUT,
    WRITE_TIMEOUT,
    decode_frame,
    encode_frame,
    valid_id,
    valid_method,
)


class RequestHandler:
    """Dispatch complete frames on the store's owning thread only."""

    def __init__(self, store: Store, kernel: Kernel):
        self.store = store
        self.kernel = kernel

    def handle(self, raw: bytes) -> bytes:
        request_id = None
        try:
            request = decode_frame(raw)
            require_keys(request, ["id", "method", "auth", "params"], ["id", "method", "auth", "params"])
            if not valid_id(request["id"]):
                raise MemoryError("invalid_request", "Request ID is invalid.")
            request_id = request["id"]
            method = request["method"]
            if not valid_method(method):
                raise MemoryError("invalid_request", "Method is invalid.")
            auth = require_keys(request["auth"], ["token"], ["token"])
            token = auth["token"]
            if not isinstance(token, str) or len(token) > 256:
                raise MemoryError("unauthorized", "The capability is invalid or revoked.")
            params = request["params"]
            if not isinstance(params, dict):
                raise MemoryError("invalid_request", "Parameters must be an object.")
            capability = self.store.authenticate(token)
            result = self.kernel.dispatch(capability, method, params)
        except MemoryError as exc:
            # Validation details can contain attacker-controlled field names.
            return self.error(request_id, exc.code, exc.message)
        except (UnicodeError, ValueError, RecursionError):
            return self.error(request_id, "invalid_json", "The local request is malformed.")
        except Exception:
            return self.error(request_id, "internal_error", "The local service could not complete the request.")
        try:
            return encode_frame({"id": request_id, "result": result})
        except (TypeError, ValueError, UnicodeError, RecursionError):
            return self.error(request_id, "response_too_large", "The local response exceeds the frame limit; narrow the request.")

    @staticmethod
    def error(request_id: Any, code: str, message: str) -> bytes:
        return encode_frame({"id": request_id, "error": {"code": code, "message": message}})


class _Connection:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buffer = bytearray()
        self.output = b""
        self.offset = 0
        self.deadline = time.monotonic() + READ_TIMEOUT


class MemoryServer:
    """Bounded nonblocking socket I/O with serialized kernel/SQLite dispatch."""

    def __init__(self, socket_path: Path, store: Store, kernel_factory: Callable[[Store], Kernel] = Kernel):
        self.handler = RequestHandler(store, kernel_factory(store))
        self.socket_path = socket_path
        self.created_socket = None
        self.selector = None
        self.connections: Dict[socket.socket, _Connection] = {}
        self.listener = None
        try:
            self.selector = selectors.DefaultSelector()
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener.bind(str(socket_path))
            self.created_socket = socket_path.lstat()
            os.chmod(str(socket_path), 0o600)
            if not same_inode(self.created_socket, ensure_private_socket(socket_path)):
                raise MemoryError("unsafe_socket", "The daemon socket changed during startup.")
            self.listener.listen(MAX_CONNECTIONS)
            self.listener.setblocking(False)
            self.selector.register(self.listener, selectors.EVENT_READ)
        except BaseException:
            self.server_close()
            raise

    def _close(self, connection: _Connection) -> None:
        self.selector.unregister(connection.sock)
        self.connections.pop(connection.sock, None)
        connection.sock.close()

    def _respond(self, connection: _Connection, output: bytes) -> None:
        connection.buffer.clear()
        connection.output = output
        connection.deadline = time.monotonic() + WRITE_TIMEOUT
        self.selector.modify(connection.sock, selectors.EVENT_WRITE, connection)

    def _accept(self) -> None:
        # Bound work per selector turn even under continuous connection attempts.
        for _ in range(MAX_CONNECTIONS):
            try:
                sock, _ = self.listener.accept()
            except BlockingIOError:
                return
            if len(self.connections) >= MAX_CONNECTIONS:
                sock.close()
                continue
            try:
                verify_peer_owner(sock)
                sock.setblocking(False)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, CHUNK_BYTES)
                connection = _Connection(sock)
                self.selector.register(sock, selectors.EVENT_READ, connection)
                self.connections[sock] = connection
            except (OSError, MemoryError):
                sock.close()

    def _read(self, connection: _Connection) -> None:
        chunk = connection.sock.recv(min(CHUNK_BYTES, MAX_FRAME_BYTES + 1 - len(connection.buffer)))
        if not chunk:
            self._close(connection)
            return
        connection.buffer.extend(chunk)
        newline = connection.buffer.find(b"\n")
        frame_size = newline + 1 if newline >= 0 else len(connection.buffer)
        if frame_size > MAX_FRAME_BYTES or (newline < 0 and frame_size == MAX_FRAME_BYTES):
            self._respond(connection, self.handler.error(None, "request_too_large", "The local request exceeds the frame limit."))
        elif newline >= 0:
            self._respond(connection, self.handler.handle(bytes(connection.buffer[:newline])))

    def _write(self, connection: _Connection) -> None:
        sent = connection.sock.send(memoryview(connection.output)[connection.offset:])
        if not sent:
            self._close(connection)
            return
        connection.offset += sent
        if connection.offset == len(connection.output):
            self._close(connection)

    def serve_forever(self, poll_interval: float = 0.25, ownership_check: Callable[[], None] = lambda: None) -> None:
        while True:
            ownership_check()
            now = time.monotonic()
            for connection in list(self.connections.values()):
                if now >= connection.deadline:
                    self._close(connection)
            nearest = min((c.deadline for c in self.connections.values()), default=now + poll_interval)
            for key, _events in self.selector.select(max(0, min(poll_interval, nearest - now))):
                ownership_check()
                if key.fileobj is self.listener:
                    self._accept()
                    continue
                connection = key.data
                if time.monotonic() >= connection.deadline:
                    self._close(connection)
                    continue
                try:
                    if connection.output:
                        self._write(connection)
                    else:
                        self._read(connection)
                except BlockingIOError:
                    pass
                except OSError:
                    self._close(connection)

    def server_close(self) -> None:
        # Every cleanup runs even if another close fails; also safe on partial
        # construction. Never unlink a replacement endpoint belonging elsewhere.
        with ExitStack() as cleanup:
            cleanup.callback(self._remove_owned_socket)
            if self.selector is not None:
                cleanup.callback(self.selector.close)
            if self.listener is not None:
                cleanup.callback(self.listener.close)
            for connection in self.connections.values():
                cleanup.callback(connection.sock.close)
            self.connections.clear()

    def _remove_owned_socket(self) -> None:
        if self.created_socket is None:
            return
        try:
            current = self.socket_path.lstat()
            if stat.S_ISSOCK(current.st_mode) and same_inode(current, self.created_socket):
                self.socket_path.unlink()
        except FileNotFoundError:
            pass
        finally:
            self.created_socket = None


def serve(data_dir: Path, kernel_factory: Callable[[Store], Kernel] = Kernel) -> None:
    if os.name == "nt":
        return _serve_windows(data_dir, kernel_factory)
    ensure_private_directory(data_dir)
    file_map = paths(data_dir)
    socket_path = file_map["socket"]
    def stop(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    with ExitStack() as cleanup:
        ownership = cleanup.enter_context(DaemonLock(data_dir))
        ownership.prepare_socket(socket_path)
        store = Store(data_dir)
        cleanup.callback(store.close)
        server = MemoryServer(socket_path, store, kernel_factory)
        cleanup.callback(server.server_close)
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous = signal.signal(signum, stop)
            cleanup.callback(signal.signal, signum, previous)
        try:
            server.serve_forever(poll_interval=0.25, ownership_check=ownership.check)
        except KeyboardInterrupt:
            pass


def _serve_windows(data_dir: Path, kernel_factory: Callable[[Store], Kernel]) -> None:
    from .security import hold_private_binding
    from .windows_runtime import PipePool, WindowsMemoryServer

    def stop(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    with ExitStack() as cleanup:
        # Guards and native endpoint ownership precede all SQLite opening. In
        # reverse order: workers, Store, pipe ownership, binding/ancestor guards.
        binding = cleanup.enter_context(hold_private_binding(paths(data_dir)["ipc_binding"]))
        pool = cleanup.enter_context(PipePool(binding))
        store = Store(data_dir)
        cleanup.callback(store.close)
        handler = RequestHandler(store, kernel_factory(store))
        server = WindowsMemoryServer(pool, handler.handle)
        cleanup.callback(server.server_close)
        signals = [signal.SIGINT, signal.SIGTERM]
        if hasattr(signal, "SIGBREAK"):
            signals.append(signal.SIGBREAK)
        for signum in signals:
            previous = signal.signal(signum, stop)
            cleanup.callback(signal.signal, signum, previous)
        try:
            server.serve_forever(ownership_check=lambda: ensure_private_directory(data_dir))
        except KeyboardInterrupt:
            pass


def main(argv: Any = None) -> int:
    parser = ContentSafeArgumentParser(prog="memoryd", description="Continuum Memory local daemon")
    parser.add_argument("--data-dir", type=Path, default=_default_home())
    args = parser.parse_args(argv)
    try:
        serve(absolute_path(args.data_dir))
        return 0
    except MemoryError as exc:
        print(canonical_json({"error": exc.as_dict()}), file=sys.stderr)
        return 2
    except OSError:
        print(canonical_json({"error": {"code": "local_io_error", "message": "The local operation could not be completed."}}), file=sys.stderr)
        return 2


def _default_home() -> Path:
    configured = os.environ.get("CONTINUUM_HOME")
    if configured:
        return Path(configured)
    return Path.home() / ".local" / "share" / "continuum-memory"


if __name__ == "__main__":
    raise SystemExit(main())
