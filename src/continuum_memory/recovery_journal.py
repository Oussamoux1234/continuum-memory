"""Private, immutable opaque locators for recovery after a CLI process exits.

A record is not an approval, a receipt, or evidence that retrying is safe. A
partial or unavailable journal must never trigger an automatic action retry.
Nothing here deletes records, including records left by failed publication.
POSIX publication flushes the file and both containing directories. Windows
uses the existing native boundary and claims process-crash recovery only.
"""

import os
import stat
from contextlib import contextmanager
from pathlib import Path

from .errors import MemoryError, invalid
from .macos_acl import require_no_acl_fd
from .recovery_locator import validate_locator
from .security import (
    _validate_open_regular, absolute_path, bounded_id, bounded_int,
    canonical_json, ensure_private_directory, path_exists,
)
from .transport import decode_frame


JOURNAL_DIRECTORY = "recovery"
MAX_LOCATOR_BYTES = 1024
MAX_JOURNAL_ENTRIES = 4096
MAX_PAGE_SIZE = 25
MAX_DIRECTORY_OBSERVATIONS = 8


def _error(code):
    messages = {
        "missing": "The recovery journal or locator is unavailable. Do not retry the action automatically.",
        "invalid": "The recovery journal is invalid. Do not retry the action automatically.",
        "conflict": "A recovery entry already exists. Its contents were not replaced.",
        "unavailable": "Recovery journal publication or access failed. Do not retry the action automatically.",
        "scan_limit": "The recovery journal listing limit was exceeded. Use a specific nonce for recovery.",
    }
    return MemoryError("recovery_journal_" + code, messages[code])


def _identity(info):
    return info.st_dev, info.st_ino


def _directory_metadata_race(before, after):
    # Concurrent entry creation changes directory ctime/link count, even when
    # its owner/mode/ACL are untouched. Retry a fresh complete ACL observation,
    # never an unsafe-permissions verdict or an identity/owner/mode change.
    fixed = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode")
    return (all(getattr(before, field) == getattr(after, field) for field in fixed)
            and before.st_ctime_ns != after.st_ctime_ns)


def _directory_fd(fd):
    for _ in range(MAX_DIRECTORY_OBSERVATIONS):
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise MemoryError("unsafe_directory", "The recovery directory must be a real directory.")
        if info.st_uid != os.getuid():
            raise MemoryError("unsafe_owner", "The recovery directory is not owned by the current user.")
        if info.st_mode & 0o077:
            raise MemoryError("unsafe_permissions", "The recovery directory is not owner-only.")
        try:
            require_no_acl_fd(fd, info)
        except MemoryError as error:
            if error.code != "unsafe_file" or not _directory_metadata_race(info, os.fstat(fd)):
                raise
        else:
            return info
    raise _error("unavailable")


def _same_directory(fd, path, *, parent_fd=None):
    held = _directory_fd(fd)
    observed = os.stat(path, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(observed.st_mode) or _identity(held) != _identity(observed):
        raise _error("unavailable")


@contextmanager
def _posix_journal(data_dir, create):
    expected = ensure_private_directory(data_dir)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    data_fd = os.open(data_dir, flags)
    try:
        if _identity(_directory_fd(data_fd)) != _identity(expected):
            raise _error("unavailable")
        if create:
            try:
                os.mkdir(JOURNAL_DIRECTORY, 0o700, dir_fd=data_fd)
            except FileExistsError:
                # Another writer may create this exact directory. Never adopt
                # its permissions: the opened directory must pass validation.
                pass
        journal_fd = os.open(JOURNAL_DIRECTORY, flags, dir_fd=data_fd)
        try:
            _same_directory(data_fd, data_dir)
            _same_directory(journal_fd, JOURNAL_DIRECTORY, parent_fd=data_fd)
            yield data_fd, journal_fd
            _same_directory(journal_fd, JOURNAL_DIRECTORY, parent_fd=data_fd)
            _same_directory(data_fd, data_dir)
        finally:
            os.close(journal_fd)
    finally:
        os.close(data_fd)


@contextmanager
def _windows_journal(data_dir, create):
    import ctypes
    from .windows_boundary import WindowsBoundary, local_path

    boundary = WindowsBoundary()
    journal = data_dir / JOURNAL_DIRECTORY
    with boundary.open_private(data_dir, directory=True):
        if create:
            # Capture the native result before releasing descriptors/handles.
            # Only ERROR_ALREADY_EXISTS can mean a concurrent creator won.
            with boundary._attributes(directory=True) as attributes:
                created = boundary.kernel.CreateDirectoryW(local_path(journal), ctypes.byref(attributes))
                error = ctypes.get_last_error() if not created else 0
            if not created and error != 183:
                raise _error("unavailable")
        elif not path_exists(journal):
            raise _error("missing")
        with boundary.open_private(journal, directory=True) as handle:
            identity = boundary._info(handle, True)
            yield boundary, journal
            if boundary._info(handle, True) != identity:
                raise _error("unavailable")


def _write_posix(journal_fd, name, raw):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(name, flags, 0o600, dir_fd=journal_fd)
    try:
        initial = _validate_open_regular(fd, "Recovery locator")
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise _error("unavailable")
            view = view[written:]
        os.fsync(fd)
        current = _validate_open_regular(fd, "Recovery locator")
        published = os.stat(name, dir_fd=journal_fd, follow_symlinks=False)
        if (_identity(initial) != _identity(current)
                or _identity(current) != _identity(published)
                or current.st_size != len(raw)):
            raise _error("unavailable")
    finally:
        os.close(fd)


def persist_locator(data_dir, locator):
    """Durably publish one opaque descriptor before sending any apply bytes.

    The same nonce always collides, even when the descriptor is identical.
    Partial files are retained; neither a later caller nor this function repairs
    them. A failed return does not authorize retrying a memory action.
    """
    locator = validate_locator(locator)
    raw = canonical_json(locator).encode("utf-8")
    if len(raw) > MAX_LOCATOR_BYTES:
        raise _error("invalid")
    data_dir = absolute_path(Path(data_dir))
    name = locator["nonce"] + ".json"
    target = data_dir / JOURNAL_DIRECTORY / name
    try:
        if os.name == "nt":
            with _windows_journal(data_dir, True) as (boundary, journal):
                if path_exists(target):
                    raise _error("conflict")
                boundary.write_new(target, raw)
                if _read_windows(boundary, target) != raw:
                    raise _error("unavailable")
        else:
            with _posix_journal(data_dir, True) as (data_fd, journal_fd):
                _write_posix(journal_fd, name, raw)
                os.fsync(journal_fd)
                # Always flush the parent too: a concurrent creator may not yet
                # have flushed its new directory entry in this process.
                os.fsync(data_fd)
        return target
    except FileExistsError:
        raise _error("conflict") from None
    except OSError:
        raise _error("unavailable") from None


def _read_posix(journal_fd, name):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(name, flags, dir_fd=journal_fd)
    try:
        initial = _validate_open_regular(fd, "Recovery locator")
        if initial.st_size > MAX_LOCATOR_BYTES:
            raise _error("invalid")
        raw = bytearray()
        while len(raw) <= MAX_LOCATOR_BYTES:
            chunk = os.read(fd, MAX_LOCATOR_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
        current = _validate_open_regular(fd, "Recovery locator")
        published = os.stat(name, dir_fd=journal_fd, follow_symlinks=False)
        changed = any(getattr(initial, field) != getattr(current, field)
                      for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))
        if changed or _identity(current) != _identity(published):
            raise _error("invalid")
        if len(raw) > MAX_LOCATOR_BYTES:
            raise _error("invalid")
        return bytes(raw)
    finally:
        os.close(fd)


def _read_windows(boundary, path):
    from .windows_boundary import GENERIC_READ
    # A read-shared handle excludes writers, truncation and deletion until the
    # bounded read and post-read native ACL/identity validation have completed.
    with boundary.open_private(path, access=GENERIC_READ, share=1) as handle:
        return boundary._read_handle(handle, MAX_LOCATOR_BYTES)


def _decode(raw, name):
    try:
        locator = validate_locator(decode_frame(raw))
    except (MemoryError, ValueError, UnicodeError, RecursionError):
        raise _error("invalid") from None
    if name != locator["nonce"] + ".json":
        raise _error("invalid")
    return locator


def _page(directory, read, nonce, after, limit):
    if nonce is not None:
        name = nonce + ".json"
        return {"locators": [_decode(read(name), name)], "next_cursor": None}
    names = []
    with os.scandir(directory) as entries:
        for entry in entries:
            if len(names) >= MAX_JOURNAL_ENTRIES:
                raise _error("scan_limit")
            try:
                if not entry.name.endswith(".json"):
                    raise _error("invalid")
                bounded_id(entry.name[:-5], "nonce")
            except MemoryError:
                raise _error("invalid") from None
            names.append(entry.name)
    selected = []
    for name in sorted(names):
        # Validate every entry, even entries outside this page. Unknown or
        # corrupt residue is never silently hidden by pagination.
        locator = _decode(read(name), name)
        if (after is None or locator["nonce"] > after) and len(selected) <= limit:
            selected.append(locator)
    more = len(selected) > limit
    return {"locators": selected[:limit],
            "next_cursor": selected[limit - 1]["nonce"] if more else None}


def load_locators(data_dir, *, nonce=None, after=None, limit=MAX_PAGE_SIZE):
    """Read bounded locator pages, or directly recover a specific nonce.

    Listing examines at most MAX_JOURNAL_ENTRIES entries and fails explicitly
    above that bound. Direct nonce lookup bypasses the scan limit and unrelated
    corrupt entries. Lexical pagination is not a snapshot under concurrent
    publication: restart listing to discover newly added earlier nonces.
    """
    limit = bounded_int(limit, "limit", 1, MAX_PAGE_SIZE)
    if nonce is not None:
        nonce = bounded_id(nonce, "nonce")
    if after is not None:
        after = bounded_id(after, "after")
    if nonce is not None and after is not None:
        raise invalid("A specific nonce cannot be combined with a listing cursor.")
    data_dir = absolute_path(Path(data_dir))
    try:
        if os.name == "nt":
            with _windows_journal(data_dir, False) as (boundary, journal):
                if nonce is not None and not path_exists(journal / (nonce + ".json")):
                    raise _error("missing")
                return _page(journal, lambda name: _read_windows(boundary, journal / name),
                             nonce, after, limit)
        with _posix_journal(data_dir, False) as (_, journal_fd):
            return _page(journal_fd, lambda name: _read_posix(journal_fd, name), nonce, after, limit)
    except FileNotFoundError:
        raise _error("missing") from None
    except OSError:
        raise _error("unavailable") from None
