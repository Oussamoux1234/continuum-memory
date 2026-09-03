"""Owner-only Unix socket daemon with a serialized request loop."""

import argparse
import json
import os
import signal
import socketserver
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Dict

from .errors import MemoryError
from .kernel import Kernel
from .security import (
    MAX_FRAME_BYTES,
    absolute_path,
    canonical_json,
    ensure_private_directory,
    ensure_private_socket,
    path_exists,
    require_keys,
)
from .storage import Store, paths


class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(MAX_FRAME_BYTES + 1)
        if len(raw) > MAX_FRAME_BYTES:
            self._write_error(None, MemoryError("request_too_large", "The local request exceeds the frame limit."))
            return
        request_id = None
        try:
            request = json.loads(raw.decode("utf-8"))
            require_keys(request, ["id", "method", "auth", "params"], ["id", "method", "auth", "params"])
            request_id = request["id"]
            if isinstance(request_id, bool) or not isinstance(request_id, (int, str)):
                raise MemoryError("invalid_request", "Request ID is invalid.")
            method = request["method"]
            if not isinstance(method, str) or len(method) > 64:
                raise MemoryError("invalid_request", "Method is invalid.")
            auth = require_keys(request["auth"], ["token"], ["token"])
            token = auth["token"]
            if not isinstance(token, str) or len(token) > 256:
                raise MemoryError("unauthorized", "The capability is invalid or revoked.")
            params = request["params"]
            if not isinstance(params, dict):
                raise MemoryError("invalid_request", "Parameters must be an object.")
            capability = self.server.store.authenticate(token)  # type: ignore[attr-defined]
            result = self.server.kernel.dispatch(capability, method, params)  # type: ignore[attr-defined]
            self._write({"id": request_id, "result": result})
        except MemoryError as exc:
            self._write_error(request_id, exc)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            self._write_error(request_id, MemoryError("invalid_json", "The local request is malformed."))
        except Exception:
            self._write_error(request_id, MemoryError("internal_error", "The local service could not complete the request."))

    def _write_error(self, request_id: Any, error: MemoryError) -> None:
        self._write({"id": request_id, "error": error.as_dict()})

    def _write(self, value: Dict[str, Any]) -> None:
        encoded = (canonical_json(value) + "\n").encode("utf-8")
        if len(encoded) > MAX_FRAME_BYTES:
            encoded = (
                canonical_json(
                    {
                        "id": value.get("id"),
                        "error": {
                            "code": "response_too_large",
                            "message": "The local response exceeds the frame limit; narrow the request.",
                        },
                    }
                )
                + "\n"
            ).encode("utf-8")
        self.wfile.write(encoded)
        self.wfile.flush()


class MemoryServer(socketserver.UnixStreamServer):
    allow_reuse_address = False

    def __init__(
        self,
        socket_path: Path,
        store: Store,
        kernel_factory: Callable[[Store], Kernel] = Kernel,
    ):
        self.store = store
        self.kernel = kernel_factory(store)
        super().__init__(str(socket_path), RequestHandler)


def serve(data_dir: Path, kernel_factory: Callable[[Store], Kernel] = Kernel) -> None:
    ensure_private_directory(data_dir)
    file_map = paths(data_dir)
    socket_path = file_map["socket"]
    if path_exists(socket_path):
        ensure_private_socket(socket_path)
        # Never guess whether an existing socket is stale; a second writer must fail closed.
        raise MemoryError("already_running", "The daemon socket already exists; remove it only after verifying no daemon runs.")
    store = Store(data_dir)
    try:
        server = MemoryServer(socket_path, store, kernel_factory)
    except Exception:
        store.close()
        raise
    os.chmod(str(socket_path), 0o600)
    created_socket = ensure_private_socket(socket_path)

    def stop(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()
        try:
            current = socket_path.lstat()
            if (
                stat.S_ISSOCK(current.st_mode)
                and current.st_dev == created_socket.st_dev
                and current.st_ino == created_socket.st_ino
            ):
                socket_path.unlink()
        except FileNotFoundError:
            pass


def main(argv: Any = None) -> int:
    parser = argparse.ArgumentParser(prog="memoryd", description="Continuum Memory local daemon")
    parser.add_argument("--data-dir", type=Path, default=_default_home())
    args = parser.parse_args(argv)
    try:
        serve(absolute_path(args.data_dir))
        return 0
    except MemoryError as exc:
        print(canonical_json({"error": exc.as_dict()}), file=sys.stderr)
        return 2


def _default_home() -> Path:
    configured = os.environ.get("CONTINUUM_HOME")
    if configured:
        return Path(configured)
    return Path.home() / ".local" / "share" / "continuum-memory"


if __name__ == "__main__":
    raise SystemExit(main())
