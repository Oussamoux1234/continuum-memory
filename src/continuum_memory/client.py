"""Bounded one-request Unix socket client used by CLI and MCP bridge."""

import os
import socket
import time
from pathlib import Path
from typing import Any, Dict

from .errors import MemoryError, UNAVAILABLE
from .peer import verify_peer_owner
from .security import MAX_FRAME_BYTES, ensure_private_directory, ensure_private_socket
from .storage import load_capability, paths
from .transport import CHUNK_BYTES, CLIENT_TIMEOUT, decode_frame, encode_frame


class DaemonClient:
    def __init__(self, data_dir: Path, capability_file: Path):
        ensure_private_directory(data_dir)
        self.data_dir = data_dir
        self.capability = load_capability(capability_file)
        self.socket_path = paths(data_dir)["socket"]

    def call(self, method: str, params: Dict[str, Any]) -> Any:
        ensure_private_directory(self.data_dir)
        request = {
            "id": 1,
            "method": method,
            "auth": {"token": self.capability["token"]},
            "params": params,
        }
        try:
            payload = encode_frame(request)
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise MemoryError("request_too_large", "The local request exceeds the frame limit.") from exc
        expected_socket = ensure_private_socket(self.socket_path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        deadline = time.monotonic() + CLIENT_TIMEOUT
        sock.settimeout(CLIENT_TIMEOUT)
        try:
            sock.connect(str(self.socket_path))
            connected_socket = ensure_private_socket(self.socket_path)
            if (
                connected_socket.st_dev != expected_socket.st_dev
                or connected_socket.st_ino != expected_socket.st_ino
            ):
                raise MemoryError("unsafe_socket", "The daemon socket changed during connection.")
            self._verify_peer_owner(sock)
            self._remaining(sock, deadline)
            sock.sendall(payload)
            chunks = bytearray()
            while len(chunks) < MAX_FRAME_BYTES:
                self._remaining(sock, deadline)
                chunk = sock.recv(min(CHUNK_BYTES, MAX_FRAME_BYTES + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
                if b"\n" in chunk:
                    break
        except (OSError, socket.timeout) as exc:
            raise UNAVAILABLE from exc
        finally:
            sock.close()
        if len(chunks) > MAX_FRAME_BYTES or b"\n" not in chunks:
            raise MemoryError("invalid_response", "The local service returned an invalid response.")
        try:
            response = decode_frame(bytes(chunks).split(b"\n", 1)[0])
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise MemoryError("invalid_response", "The local service returned malformed JSON.") from exc
        if (not isinstance(response, dict) or type(response.get("id")) is not int or response["id"] != 1
                or set(response) not in ({"id", "result"}, {"id", "error"})):
            raise MemoryError("invalid_response", "The local service returned an invalid response.")
        if "error" in response:
            error = response["error"]
            if (not isinstance(error, dict) or not isinstance(error.get("code"), str)
                    or not isinstance(error.get("message"), str)):
                raise MemoryError("invalid_response", "The local service returned an invalid error.")
            raise MemoryError(error["code"], error["message"])
        return response["result"]

    @staticmethod
    def _remaining(sock: socket.socket, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("Local request deadline expired")
        sock.settimeout(remaining)

    @staticmethod
    def _verify_peer_owner(sock: socket.socket) -> None:
        verify_peer_owner(sock)
