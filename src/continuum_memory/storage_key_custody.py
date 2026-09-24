"""Fixed-name rotation file custody; no native cipher or approval decisions.

Callers own the daemon lease, authenticated operation and fresh owner approval.
These helpers avoid creating a third raw-key file. They do not erase historical
keys, protect against an unrestricted same-UID process, or prove power-loss safety.
"""

from contextlib import contextmanager
import hashlib
import hmac
import os
from pathlib import Path
import stat

from .errors import MemoryError
from .security import _validate_open_regular, ensure_private_directory


MAX_DIRECTORY_ENTRIES = 4096
MATERIAL_LIMITS = {"storage.key": 32, "storage.key.next": 32, "storage.rotation.json": 4096}


def _refuse():
    raise MemoryError("rotation_recovery_refused", "Storage-key custody could not be validated; preserved material requires investigation.") from None


def _identity(info):
    return info.st_dev, info.st_ino


def _fingerprint(info):
    return (_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_nlink)


def _check_directory(data_dir, descriptor):
    current = ensure_private_directory(data_dir)
    opened = os.fstat(descriptor)
    if (not stat.S_ISDIR(opened.st_mode) or opened.st_uid != os.getuid()
            or opened.st_mode & 0o077 or _identity(current) != _identity(opened)):
        _refuse()


@contextmanager
def _directory(data_dir):
    descriptor = None
    try:
        expected = ensure_private_directory(data_dir)
        descriptor = os.open(str(data_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        _check_directory(data_dir, descriptor)
        if _identity(expected) != _identity(os.fstat(descriptor)):
            _refuse()
        yield descriptor
    except (OSError, ValueError, MemoryError):
        _refuse()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def require_no_legacy_key_residue(data_dir):
    """Detect reserved legacy names, without reading, following or deleting them."""
    with _directory(Path(data_dir)) as directory:
        with os.scandir(directory) as entries:
            for count, entry in enumerate(entries, 1):
                if count > MAX_DIRECTORY_ENTRIES:
                    _refuse()
                # Also refuse malformed names in the reserved legacy namespace.
                # A match is not evidence that a file is ours or safe to remove.
                if entry.name.startswith(".storage.key.") and entry.name.endswith(".tmp"):
                    raise MemoryError("rotation_pending", "Unexpected storage-key residue requires owner investigation before using the vault.")
        _check_directory(Path(data_dir), directory)


def _valid_digest(value):
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        _refuse()


def _open_material(directory, name):
    if name not in MATERIAL_LIMITS:
        _refuse()
    expected = os.stat(name, dir_fd=directory, follow_symlinks=False)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
    try:
        opened = _validate_open_regular(descriptor, "Storage rotation material")
        maximum = MATERIAL_LIMITS[name]
        if (_fingerprint(expected) != _fingerprint(opened) or not 0 < opened.st_size <= maximum
                or (name != "storage.rotation.json" and opened.st_size != 32)):
            _refuse()
        payload = bytearray()
        while len(payload) <= maximum:
            chunk = os.read(descriptor, maximum + 1 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
        _check_material(directory, name, descriptor, opened)
        if len(payload) != opened.st_size:
            _refuse()
        return descriptor, opened, hashlib.sha256(payload).hexdigest()
    except BaseException:
        os.close(descriptor)
        raise


def _check_material(directory, name, descriptor, expected):
    opened = _validate_open_regular(descriptor, "Storage rotation material")
    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if _fingerprint(opened) != _fingerprint(expected) or _fingerprint(current) != _fingerprint(expected):
        _refuse()


def promote_prepared_key(data_dir, old_key_sha256, new_key_sha256):
    """Publish an already-durable next-key inode, or re-sync a prior publication.

    Never select a database key here: the caller must already have proved the
    unique new-key database/audit/generation state on independent native copies.
    A matching duplicate next key is retained for the caller's verified cleanup.
    """
    data_dir = Path(data_dir)
    _valid_digest(old_key_sha256)
    _valid_digest(new_key_sha256)
    if hmac.compare_digest(old_key_sha256, new_key_sha256):
        _refuse()
    require_no_legacy_key_residue(data_dir)
    active = staged = None
    try:
        with _directory(data_dir) as directory:
            active, active_info, active_hash = _open_material(directory, "storage.key")
            try:
                staged, staged_info, staged_hash = _open_material(directory, "storage.key.next")
            except FileNotFoundError:
                staged_hash = None
            if active_hash not in {old_key_sha256, new_key_sha256} or staged_hash not in {None, new_key_sha256}:
                _refuse()
            if active_hash == new_key_sha256:
                _check_material(directory, "storage.key", active, active_info)
                os.fsync(active)
                _check_directory(data_dir, directory)
                os.fsync(directory)
                _check_material(directory, "storage.key", active, active_info)
                _check_directory(data_dir, directory)
                return
            if staged is None:
                _refuse()
            os.fsync(staged)
            _check_directory(data_dir, directory)
            os.fsync(directory)
            _check_material(directory, "storage.key", active, active_info)
            _check_material(directory, "storage.key.next", staged, staged_info)
            _check_directory(data_dir, directory)
            os.replace("storage.key.next", "storage.key", src_dir_fd=directory, dst_dir_fd=directory)
            published, published_info, published_hash = _open_material(directory, "storage.key")
            try:
                if _identity(published_info) != _identity(staged_info) or published_hash != new_key_sha256:
                    _refuse()
                _check_directory(data_dir, directory)
                os.fsync(directory)
                _check_material(directory, "storage.key", published, published_info)
                _check_directory(data_dir, directory)
            finally:
                os.close(published)
    finally:
        if staged is not None:
            os.close(staged)
        if active is not None:
            os.close(active)


def remove_verified_rotation_material(data_dir, name, expected_sha256):
    """Remove one exact approved control-file inode; never search or repair."""
    if name not in {"storage.key.next", "storage.rotation.json"}:
        _refuse()
    _valid_digest(expected_sha256)
    data_dir = Path(data_dir)
    require_no_legacy_key_residue(data_dir)
    with _directory(data_dir) as directory:
        descriptor, expected, digest = _open_material(directory, name)
        try:
            if not hmac.compare_digest(digest, expected_sha256):
                _refuse()
            _check_material(directory, name, descriptor, expected)
            _check_directory(data_dir, directory)
            os.unlink(name, dir_fd=directory)
            os.fsync(directory)
            _check_directory(data_dir, directory)
        finally:
            os.close(descriptor)
