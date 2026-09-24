"""Conservative native macOS ACL observations, not same-user isolation.

Only ACL-free objects are accepted. No permission repair or ACL interpretation is
performed. The reviewed native filesystem is local APFS; see MACOS_BOUNDARY.md.
"""

import ctypes
import errno
import os
import stat
import sys
from functools import lru_cache
from pathlib import Path

from .errors import MemoryError

ACL_TYPE_EXTENDED = 0x100
ACL_FIRST_ENTRY = 0
# Darwin's stable fcntl ABI; older supported Python versions do not export it.
DARWIN_O_EVTONLY = 0x8000
MAX_ACL_BYTES = 1024 * 1024


@lru_cache(maxsize=1)
def _library():
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    signatures = {
        "acl_get_fd_np": ([ctypes.c_int, ctypes.c_int], ctypes.c_void_p),
        "acl_get_link_np": ([ctypes.c_char_p, ctypes.c_int], ctypes.c_void_p),
        "acl_init": ([ctypes.c_int], ctypes.c_void_p),
        "acl_valid": ([ctypes.c_void_p], ctypes.c_int),
        "acl_size": ([ctypes.c_void_p], ctypes.c_ssize_t),
        "acl_get_entry": ([ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)], ctypes.c_int),
        "acl_free": ([ctypes.c_void_p], ctypes.c_int),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = result
    return library


def _size(library, acl):
    if library.acl_valid(acl) != 0:
        raise ValueError("Invalid ACL")
    size = library.acl_size(acl)
    if not 0 < size <= MAX_ACL_BYTES:
        raise ValueError("Invalid ACL size")
    return size


def _free(library, acl):
    if library.acl_free(acl) != 0:
        raise ValueError("ACL release failed")


def _check_acl(library, query, target):
    ctypes.set_errno(0)
    acl = query(target, ACL_TYPE_EXTENDED)
    query_errno = ctypes.get_errno()
    if not acl:
        # Darwin reports absent FILESEC_ACL as ENOENT, not an allocated empty
        # ACL. Callers MUST corroborate unchanged existing-object metadata.
        if query_errno == errno.ENOENT:
            return
        raise ValueError("ACL query failed")
    try:
        empty = library.acl_init(0)
        if not empty:
            raise ValueError("Empty ACL baseline unavailable")
        try:
            empty_size = _size(library, empty)
        finally:
            _free(library, empty)
        if _size(library, acl) != empty_size:
            raise MemoryError("unsafe_permissions", "Private material must not have extended ACL entries.")
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        result = library.acl_get_entry(acl, ACL_FIRST_ENTRY, ctypes.byref(entry))
        # On Darwin end-of-list is -1/EINVAL, which alone is also an error.
        # Accept only a valid object the same size as a native empty baseline,
        # with no output entry. Do not inspect opaque structures or ACL text.
        if result != -1 or ctypes.get_errno() != errno.EINVAL or entry.value is not None:
            raise ValueError("ACL emptiness could not be verified")
    finally:
        _free(library, acl)


def _unchanged(expected, observed):
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_ctime_ns")
    if any(getattr(expected, field) != getattr(observed, field) for field in fields):
        raise MemoryError("unsafe_file", "Private material changed during permission validation.")


def require_no_acl_fd(fd: int, expected: os.stat_result) -> None:
    """Check the already type/owner/mode-validated descriptor before any bytes."""
    if sys.platform != "darwin":
        return
    try:
        _unchanged(expected, os.fstat(fd))
        library = _library()
        _check_acl(library, library.acl_get_fd_np, fd)
        _unchanged(expected, os.fstat(fd))
    except (OSError, AttributeError, TypeError, ValueError) as error:
        raise MemoryError("acl_unavailable", "Native private-material permissions could not be verified.") from error


def require_no_acl_path(path: Path, expected: os.stat_result) -> None:
    """Bind files/directories to a nofollow metadata FD; sockets use lstat checks."""
    if sys.platform != "darwin":
        return
    try:
        _unchanged(expected, path.lstat())
        if stat.S_ISSOCK(expected.st_mode):
            # macOS cannot open a Unix socket pathname even with O_EVTONLY.
            # acl_get_link_np does not follow a final symlink. This remains a
            # pathname observation, NOT descriptor-bound/ABA-proof validation.
            library = _library()
            _check_acl(library, library.acl_get_link_np, os.fsencode(path))
        else:
            # O_EVTONLY obtains metadata without opening a raced device/FIFO
            # for content IO. Missing safety flags never get a weaker fallback.
            fd = os.open(path, DARWIN_O_EVTONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                require_no_acl_fd(fd, expected)
            finally:
                os.close(fd)
        _unchanged(expected, path.lstat())
    except (OSError, AttributeError, TypeError, ValueError) as error:
        raise MemoryError("acl_unavailable", "Native private-material permissions could not be verified.") from error
