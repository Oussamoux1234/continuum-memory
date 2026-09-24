"""Fail-closed connected Unix peer credentials, not same-user authentication."""

import ctypes
import os
import socket
import struct
import sys

from .errors import MemoryError


def _darwin_peer_uid(sock: socket.socket) -> int:
    # Darwin uid_t/gid_t are unsigned 32-bit values. Load the fixed OS library,
    # never a caller-controlled library search path or platform Python extension.
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    getpeereid = library.getpeereid
    getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    getpeereid.restype = ctypes.c_int
    uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
    ctypes.set_errno(0)
    if getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
        raise OSError(ctypes.get_errno(), "Unix peer credentials unavailable")
    return uid.value


def peer_uid(sock: socket.socket) -> int:
    """Return kernel-supplied UID or reject; an absent API never means success."""
    try:
        if sys.platform == "darwin":
            uid = _darwin_peer_uid(sock)
            if uid == 0xFFFFFFFF:
                raise ValueError("Invalid credentials")
            return uid
        if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
            size = struct.calcsize("iII")
            credentials = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
            if len(credentials) != size:
                raise ValueError("Incomplete credentials")
            pid, uid, _gid = struct.unpack("iII", credentials)
            if pid <= 0 or uid == 0xFFFFFFFF:
                raise ValueError("Invalid credentials")
            return uid
        raise ValueError("Unsupported peer credential interface")
    except (OSError, AttributeError, TypeError, ValueError, struct.error) as error:
        raise MemoryError("peer_credentials_unavailable", "The local peer identity could not be verified.") from error


def verify_peer_owner(sock: socket.socket) -> None:
    if peer_uid(sock) != os.geteuid():
        raise MemoryError("unsafe_owner", "The local peer is not owned by the current user.")
