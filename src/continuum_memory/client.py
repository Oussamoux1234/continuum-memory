"""Bounded one-request Unix socket client used by CLI and MCP bridge."""

import json
import os
import socket
import struct
from pathlib import Path
from typing import Any, Dict

from .errors import MemoryError, UNAVAILABLE
from .security import MAX_FRAME_BYTES, canonical_json, ensure_private_directory, ensure_private_socket
from .storage import load_capability, paths


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
        payload = (canonical_json(request) + "\n").encode("utf-8")
        if len(payload) > MAX_FRAME_BYTES:
            raise MemoryError("request_too_large", "The local request exceeds the frame limit.")
        expected_socket = ensure_private_socket(self.socket_path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect(str(self.socket_path))
            connected_socket = ensure_private_socket(self.socket_path)
            if (
                connected_socket.st_dev != expected_socket.st_dev
                or connected_socket.st_ino != expected_socket.st_ino
            ):
                raise MemoryError("unsafe_socket", "The daemon socket changed during connection.")
            self._verify_peer_owner(sock)
            sock.sendall(payload)
            chunks = bytearray()
            while len(chunks) <= MAX_FRAME_BYTES:
                chunk = sock.recv(min(8192, MAX_FRAME_BYTES + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
                if b"\n" in chunk:
                    break
        except (OSError, socket.timeout) as exc:
            raise UNAVAILABLE from exc
        finally:
            sock.close()
        if len(chunks) > MAX_FRAME_BYTES or not chunks:
            raise MemoryError("invalid_response", "The local service returned an invalid response.")
        try:
            response = json.loads(bytes(chunks).split(b"\n", 1)[0].decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise MemoryError("invalid_response", "The local service returned malformed JSON.") from exc
        if response.get("error"):
            error = response["error"]
            raise MemoryError(error.get("code", "internal_error"), error.get("message", "Request failed."), error.get("details"))
        return response.get("result")

    @staticmethod
    def _verify_peer_owner(sock: socket.socket) -> None:
        peer_uid = None
        getpeereid = getattr(sock, "getpeereid", None)
        if getpeereid is not None:
            peer_uid, _peer_gid = getpeereid()
        elif hasattr(socket, "SO_PEERCRED"):
            credentials = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, peer_uid, _gid = struct.unpack("3i", credentials)
        if peer_uid is not None and peer_uid != os.getuid():
            raise MemoryError("unsafe_owner", "The daemon process is not owned by the current user.")
