"""Cooperating local POSIX daemon ownership; never a same-UID security boundary."""

import errno
import os
import socket
from pathlib import Path

from .errors import MemoryError
from .security import (
    _validate_open_regular,
    ensure_private_directory,
    ensure_private_regular,
    ensure_private_socket,
    path_exists,
)

LOCK_MARKER = b"continuum-memory-daemon-lock-v1\n"
PROBE_TIMEOUT = 0.5


def same_inode(left, right):
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


class DaemonLock:
    """Hold one persistent inode from before Store opening through cleanup.

    The file is deliberately never unlinked: a pathname's disappearance must not
    turn a second open into a different, independently lockable inode. No PID is
    used as authority and no existing lock-file contents are truncated.
    """

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.path = data_dir / "memoryd.lock"
        self.fd = None

    def __enter__(self):
        try:
            import fcntl
        except ImportError:
            raise MemoryError("unsupported_platform", "The daemon requires local POSIX file locking.") from None
        if not hasattr(os, "O_NOFOLLOW"):
            raise MemoryError("unsupported_platform", "The daemon requires no-follow file opens.")
        ensure_private_directory(self.data_dir)
        if path_exists(self.path):
            ensure_private_regular(self.path, "Daemon lock")
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        self.fd = os.open(str(self.path), flags, 0o600)
        try:
            os.set_inheritable(self.fd, False)
            _validate_open_regular(self.fd, "Daemon lock")
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN):
                    raise MemoryError("already_running", "Another daemon holds the vault lock.") from None
                raise
            self.check()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def check(self):
        ensure_private_directory(self.data_dir)
        opened = _validate_open_regular(self.fd, "Daemon lock")
        current = ensure_private_regular(self.path, "Daemon lock")
        if not same_inode(opened, current):
            raise MemoryError("daemon_lock_changed", "The daemon lock identity changed; stop and investigate.")

    def prepare_socket(self, socket_path: Path):
        self.check()
        os.lseek(self.fd, 0, os.SEEK_SET)
        marker = os.read(self.fd, len(LOCK_MARKER) + 1)
        if marker not in (b"", LOCK_MARKER):
            raise MemoryError("daemon_lock_invalid", "The daemon lock marker is invalid; stop and investigate.")
        existing = ensure_private_socket(socket_path) if path_exists(socket_path) else None
        if not marker:
            # Do not mark failed first adoption: a retry must not gain permission
            # to remove a legacy socket, including a listener still starting up.
            if existing is not None:
                raise MemoryError("stale_socket_unverified", "An unverified socket remains; complete the offline upgrade procedure.")
            remaining = memoryview(LOCK_MARKER)
            while remaining:
                written = os.write(self.fd, remaining)
                if written <= 0:
                    raise OSError("Daemon lock marker write failed")
                remaining = remaining[written:]
            os.fsync(self.fd)
        if existing is None:
            return
        # New-version contenders cannot be between bind/listen: they must own
        # this lock first. Mixed-version concurrent operation is not supported.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(PROBE_TIMEOUT)
            try:
                probe.connect(str(socket_path))
            except OSError as exc:
                if exc.errno != errno.ECONNREFUSED:
                    raise MemoryError("socket_state_unknown", "The existing socket state is uncertain; no recovery was attempted.") from None
            else:
                raise MemoryError("already_running", "A listener still owns the existing socket.")
        self.check()
        current = ensure_private_socket(socket_path)
        if not same_inode(existing, current):
            raise MemoryError("unsafe_socket", "The daemon socket changed during recovery.")
        socket_path.unlink()

    def __exit__(self, _type, _value, _traceback):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)
