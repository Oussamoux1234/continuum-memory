import ctypes
import os
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from continuum_memory.client import DaemonClient
from continuum_memory.daemon import MemoryServer
from continuum_memory.errors import MemoryError
from continuum_memory.peer import peer_uid, verify_peer_owner
from continuum_memory.security import ensure_private_socket
from continuum_memory.storage import Store, paths


class PeerCredentialTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "Native Unix peer UID; Windows verifies process-token SIDs")
    def test_connected_native_socket_pair_has_kernel_effective_uid(self):
        first, second = socket.socketpair()
        try:
            self.assertEqual(peer_uid(first), os.geteuid())
            self.assertEqual(peer_uid(second), os.geteuid())
            verify_peer_owner(first)
        finally:
            first.close()
            second.close()

    @unittest.skipUnless(os.name == "posix", "Native Unix socket; Windows pipe closure is tested separately")
    def test_closed_socket_fails_closed(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.close()
        with self.assertRaises(MemoryError) as caught:
            peer_uid(sock)
        self.assertEqual(caught.exception.code, "peer_credentials_unavailable")

    def test_unavailable_platform_has_no_permissive_fallback(self):
        with patch("continuum_memory.peer.sys.platform", "unsupported"):
            with self.assertRaises(MemoryError) as caught:
                peer_uid(Mock())
        self.assertEqual(caught.exception.code, "peer_credentials_unavailable")

    def test_linux_short_failed_and_invalid_credentials_fail_closed(self):
        for value in (b"short", struct.pack("iII", 0, 0, 0), struct.pack("iII", 1, 0xFFFFFFFF, 0)):
            with self.subTest(value=value), patch("continuum_memory.peer.sys.platform", "linux"), patch.object(socket, "SO_PEERCRED", 17, create=True):
                sock = Mock()
                sock.getsockopt.return_value = value
                with self.assertRaises(MemoryError):
                    peer_uid(sock)
        with patch("continuum_memory.peer.sys.platform", "linux"), patch.object(socket, "SO_PEERCRED", 17, create=True):
            sock = Mock()
            sock.getsockopt.side_effect = OSError("synthetic failure")
            with self.assertRaises(MemoryError):
                peer_uid(sock)

    def test_linux_unsigned_uid_abi_is_preserved(self):
        with patch("continuum_memory.peer.sys.platform", "linux"), patch.object(socket, "SO_PEERCRED", 17, create=True):
            sock = Mock()
            sock.getsockopt.return_value = struct.pack("iII", 123, 3000000000, 3000000001)
            self.assertEqual(peer_uid(sock), 3000000000)

    def test_darwin_native_error_and_missing_symbol_are_fail_closed(self):
        for failure in (OSError("missing library"), AttributeError("missing symbol")):
            with patch("continuum_memory.peer.sys.platform", "darwin"), patch("continuum_memory.peer.ctypes.CDLL", side_effect=failure):
                with self.assertRaises(MemoryError) as caught:
                    peer_uid(Mock())
            self.assertEqual(caught.exception.code, "peer_credentials_unavailable")
        library = Mock()
        library.getpeereid.return_value = -1
        with patch("continuum_memory.peer.sys.platform", "darwin"), patch("continuum_memory.peer.ctypes.CDLL", return_value=library):
            with self.assertRaises(MemoryError):
                peer_uid(Mock())
        self.assertEqual(library.getpeereid.restype, ctypes.c_int)
        self.assertEqual(library.getpeereid.argtypes, [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)])

    def test_wrong_uid_injection_is_rejected(self):
        # Explicit Unix-contract fixture IDs, not a synthetic production Windows UID.
        with patch("continuum_memory.peer.peer_uid", return_value=1002), patch("continuum_memory.peer.os.geteuid", return_value=1001, create=True):
            with self.assertRaises(MemoryError) as caught:
                verify_peer_owner(Mock())
        self.assertEqual(caught.exception.code, "unsafe_owner")

    def test_darwin_invalid_uid_sentinel_fails_closed(self):
        with patch("continuum_memory.peer.sys.platform", "darwin"), patch("continuum_memory.peer._darwin_peer_uid", return_value=0xFFFFFFFF):
            with self.assertRaises(MemoryError) as caught:
                peer_uid(Mock())
        self.assertEqual(caught.exception.code, "peer_credentials_unavailable")


@unittest.skipUnless(os.name == "posix", "Unix socket peer contract; Windows uses native pipe/peer-token checks")
class PeerTransportBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cm-peer-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        Store.bootstrap(self.home, [{"name": "peer", "path_hint": "/fixture/peer", "providers": ["codex"]}])
        self.path = paths(self.home)["socket"]
        self.client = DaemonClient(self.home, paths(self.home)["control"])

    def listener(self, path):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind(str(path))
        os.chmod(path, 0o600)
        sock.listen(2)
        sock.settimeout(2)
        return sock

    def test_replaced_endpoint_is_rejected_before_any_capability_byte(self):
        original = self.listener(self.path)
        alternate = self.home / "alternate.sock"
        replacement = self.listener(alternate)
        calls = 0
        def replace_after_initial_validation(path):
            nonlocal calls
            info = ensure_private_socket(path)
            calls += 1
            if calls == 1:
                self.path.unlink()
                alternate.rename(self.path)
            return info
        with patch("continuum_memory.client.ensure_private_socket", side_effect=replace_after_initial_validation):
            with self.assertRaises(MemoryError) as caught:
                self.client.call("status", {})
        self.assertEqual(caught.exception.code, "unsafe_socket")
        connected, _ = replacement.accept()
        with connected:
            connected.settimeout(2)
            self.assertEqual(connected.recv(1), b"")

    def test_unverifiable_server_is_rejected_before_any_capability_byte(self):
        listener = self.listener(self.path)
        failure = MemoryError("peer_credentials_unavailable", "Synthetic unavailable peer")
        with patch("continuum_memory.client.verify_peer_owner", side_effect=failure):
            with self.assertRaises(MemoryError) as caught:
                self.client.call("status", {})
        self.assertEqual(caught.exception.code, "peer_credentials_unavailable")
        connected, _ = listener.accept()
        with connected:
            connected.settimeout(2)
            self.assertEqual(connected.recv(1), b"")

    def test_daemon_rejects_unverifiable_or_foreign_peer_before_request_read(self):
        store = Store(self.home)
        self.addCleanup(store.close)
        server = MemoryServer(self.path, store)
        self.addCleanup(server.server_close)
        for code in ("peer_credentials_unavailable", "unsafe_owner"):
            with self.subTest(code=code), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(str(self.path))
                with patch("continuum_memory.daemon.verify_peer_owner", side_effect=MemoryError(code, "Synthetic rejection")):
                    server._accept()
                self.assertEqual(server.connections, {})
                self.assertEqual(client.recv(1), b"")


if __name__ == "__main__":
    unittest.main()
