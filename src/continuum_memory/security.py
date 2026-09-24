"""Canonicalization, capability, preview-grant, and bounded-input helpers."""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .errors import MemoryError, invalid

MAX_FRAME_BYTES = 65_536
MAX_BODY_BYTES = 4_096
MAX_SUBJECT_BYTES = 256
MAX_QUERY_BYTES = 256
MAX_REASON_BYTES = 512
MAX_ID_BYTES = 128
MAX_RESULTS = 25
MIN_CONTEXT_BYTES = 256
MAX_CONTEXT_BYTES = 8_192
GRANT_TTL_SECONDS = 120

ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
PROVIDER_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
TOKEN_RE = re.compile(r"[\w][\w.-]{0,63}", re.UNICODE)


def canonical_json(value: Any) -> str:
    """Deterministic JSON for local digests; this is not an RFC 8785 claim."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def random_id(prefix: str) -> str:
    return "%s_%s" % (prefix, secrets.token_urlsafe(18).rstrip("="))


def bounded_text(value: Any, field: str, maximum: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise invalid("Expected a string.", field)
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise invalid("Text must be valid UTF-8.", field) from None
    if (not allow_empty and size == 0) or size > maximum:
        raise invalid("String length is outside the allowed range.", field)
    if "\x00" in value:
        raise invalid("NUL bytes are not allowed.", field)
    return value


def bounded_id(value: Any, field: str) -> str:
    value = bounded_text(value, field, MAX_ID_BYTES)
    if not ID_RE.fullmatch(value):
        raise invalid("Identifier format is invalid.", field)
    return value


def bounded_provider(value: Any, field: str = "provider") -> str:
    value = bounded_text(value, field, 32)
    if not PROVIDER_RE.fullmatch(value) or value == "user_control":
        raise invalid("Provider format is invalid.", field)
    return value


def is_owner_capability(capability: Dict[str, Any]) -> bool:
    """Only authenticated, unbound control authority can request owner views."""
    return ("project_id" in capability and capability["project_id"] is None
            and capability.get("provider") == "user_control"
            and isinstance(capability.get("permissions"), list)
            and "control" in capability["permissions"])


def validate_capability_authority(capability: Dict[str, Any]) -> None:
    """Refuse legacy reserved-label collisions, including already-issued tokens."""
    permissions = capability.get("permissions")
    if not isinstance(permissions, list) or not all(isinstance(item, str) for item in permissions):
        raise MemoryError("forbidden", "The capability authority is invalid.")
    if is_owner_capability(capability):
        return
    if capability.get("project_id") is None or "control" in permissions:
        raise MemoryError("forbidden", "The capability authority is invalid.")
    try:
        bounded_provider(capability.get("provider"))
    except MemoryError:
        raise MemoryError("forbidden", "The capability authority is invalid.") from None


def require_keys(value: Any, allowed: Iterable[str], required: Iterable[str] = ()) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise invalid("Expected an object.")
    allowed_set = set(allowed)
    unknown = sorted(set(value) - allowed_set)
    if unknown:
        raise MemoryError("unknown_field", "Unknown request field.")
    missing = sorted(set(required) - set(value))
    if missing:
        raise MemoryError("missing_field", "Required request field is missing.", {"fields": missing})
    return value


def bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise invalid("Integer is outside the allowed range.", field)
    return value


def parse_disclosure(value: Any) -> List[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        raise invalid("Disclosure must contain one to eight providers.", "disclosure")
    providers = []
    for item in value:
        provider = "*" if item == "*" else bounded_provider(item, "disclosure")
        if provider not in providers:
            providers.append(provider)
    return sorted(providers)


def fts_literal_query(query: str) -> str:
    tokens = TOKEN_RE.findall(query)
    if not tokens:
        raise invalid("Query has no searchable tokens.", "query")
    # The tokenizer emits tokens; quoting every token prevents caller-controlled FTS syntax.
    return " OR ".join('"%s"' % token.replace('"', '""') for token in tokens[:16])


def reject_obvious_secrets(values: Iterable[str]) -> None:
    """Compatibility helper using the default admission policy."""
    from .admission import AdmissionPolicy
    AdmissionPolicy().check(values)


class ContentSafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        # argparse messages can quote invalid choices, values and unknown options.
        self.exit(2, canonical_json({"error": {"code": "invalid_arguments",
                                             "message": "Command-line arguments are invalid."}}) + "\n")


def sign_grant(control_key: bytes, nonce: str, operation: str, digest: str) -> str:
    payload = canonical_json({"digest": digest, "nonce": nonce, "operation": operation})
    return hmac.new(control_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_grant(control_key: bytes, nonce: str, operation: str, digest: str, grant: str) -> bool:
    return hmac.compare_digest(sign_grant(control_key, nonce, operation, digest), grant)


def path_exists(path: Path) -> bool:
    """Like lexists: broken symlinks still count as occupied paths."""
    return os.path.lexists(str(path))


def absolute_path(path: Path) -> Path:
    """Make a path absolute without following its final symlink."""
    return Path(os.path.abspath(str(path)))


def _reject_untrusted_symlink_ancestors(path: Path) -> None:
    """Permit only root-owned platform symlinks (for example macOS /var) in ancestors."""
    absolute = absolute_path(path)
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode) and info.st_uid != 0:
            raise MemoryError("unsafe_directory", "A private path has an untrusted symlink ancestor.")


def ensure_safe_ancestors(path: Path) -> None:
    if os.name == "nt":
        from .windows_boundary import WindowsBoundary, local_path
        with WindowsBoundary()._parents(local_path(path / "boundary-probe")):
            return
    _reject_untrusted_symlink_ancestors(path)


def create_private_directory(path: Path, parents: bool = False) -> None:
    """Create owner-only directories; never tighten or adopt an existing object."""
    if os.name == "nt":
        from .windows_boundary import WindowsBoundary
        boundary = WindowsBoundary()
        missing = [path]
        if parents:
            while not path_exists(missing[-1].parent):
                missing.append(missing[-1].parent)
        for directory in reversed(missing):
            boundary.create_directory(directory)
        return
    ensure_safe_ancestors(path.parent)
    path.mkdir(mode=0o700, parents=parents)
    ensure_private_directory(path)


def ensure_private_directory(path: Path):
    if os.name == "nt":
        from .windows_boundary import WindowsBoundary
        return WindowsBoundary().inspect(path, directory=True)
    _reject_untrusted_symlink_ancestors(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise MemoryError("unsafe_directory", "The private data directory does not exist.") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise MemoryError("unsafe_directory", "The private data path must be a real directory, not a link.")
    if info.st_uid != os.getuid():
        raise MemoryError("unsafe_owner", "The private data directory is not owned by the current user.")
    if info.st_mode & 0o077:
        raise MemoryError("unsafe_permissions", "The private data directory is not owner-only.")
    return info


def ensure_private_regular(path: Path, label: str = "Private material"):
    if os.name == "nt":
        from .windows_boundary import WindowsBoundary
        return WindowsBoundary().inspect(path)
    _reject_untrusted_symlink_ancestors(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise MemoryError("unsafe_file", "%s is missing." % label) from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise MemoryError("unsafe_file", "%s must be a single regular file, not a link." % label)
    if info.st_uid != os.getuid():
        raise MemoryError("unsafe_owner", "%s is not owned by the current user." % label)
    if info.st_mode & 0o077:
        raise MemoryError("unsafe_permissions", "%s is not owner-only." % label)
    return info


def ensure_private_socket(path: Path) -> os.stat_result:
    _reject_untrusted_symlink_ancestors(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise MemoryError("unsafe_socket", "The daemon socket does not exist.") from exc
    if not stat.S_ISSOCK(info.st_mode) or info.st_nlink != 1:
        raise MemoryError("unsafe_socket", "The daemon socket path must be a real Unix socket, not a link.")
    if info.st_uid != os.getuid():
        raise MemoryError("unsafe_owner", "The daemon socket is not owned by the current user.")
    if info.st_mode & 0o077:
        raise MemoryError("unsafe_permissions", "The daemon socket is not owner-only.")
    return info


def _validate_open_regular(fd: int, label: str) -> os.stat_result:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise MemoryError("unsafe_file", "%s must be a single regular file." % label)
    if info.st_uid != os.getuid():
        raise MemoryError("unsafe_owner", "%s is not owned by the current user." % label)
    if info.st_mode & 0o077:
        raise MemoryError("unsafe_permissions", "%s is not owner-only." % label)
    return info


def write_private(path: Path, data: bytes) -> None:
    if os.name == "nt":
        from .windows_boundary import WindowsBoundary
        WindowsBoundary().write_new(path, data)
        return
    ensure_private_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    try:
        _validate_open_regular(fd, "Private material")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while creating private file")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def replace_private(path: Path, data: bytes) -> None:
    if os.name == "nt":
        from .windows_boundary import WindowsBoundary
        WindowsBoundary().replace(path, data)
        return
    ensure_private_directory(path.parent)
    if path_exists(path):
        ensure_private_regular(path)
    temporary = path.with_name(".%s.%s.tmp" % (path.name, secrets.token_hex(6)))
    try:
        write_private(temporary, data)
        os.replace(str(temporary), str(path))
        ensure_private_regular(path)
        directory_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def read_private(path: Path, maximum: int = 4096) -> bytes:
    if os.name == "nt":
        from .windows_boundary import WindowsBoundary
        return WindowsBoundary().read(path, maximum)
    ensure_private_directory(path.parent)
    # Only regular files are valid; a raced-in FIFO must not block before fstat.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise MemoryError("unsafe_file", "Private material could not be opened safely.") from exc
    try:
        _validate_open_regular(fd, "Private material")
        chunks = bytearray()
        while len(chunks) <= maximum:
            chunk = os.read(fd, min(4096, maximum + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) > maximum:
            raise MemoryError("unsafe_file", "Private material is unexpectedly large.")
        _validate_open_regular(fd, "Private material")
        return bytes(chunks)
    finally:
        os.close(fd)


@contextmanager
def hold_private_binding(path: Path):
    """Windows-only lifetime guard for the immutable nonsecret IPC identity."""
    from .windows_boundary import WindowsBoundary
    with WindowsBoundary().hold_binding(path) as binding:
        yield binding


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
