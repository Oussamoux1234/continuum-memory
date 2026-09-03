"""Linux approval proof contract and root-owned key boundary."""

import base64
import binascii
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from .errors import MemoryError
from .security import GRANT_TTL_SECONDS, ID_RE, canonical_json, digest_json, path_exists


APPROVAL_SCHEMA_VERSION = 1
APPROVAL_OPERATIONS = {
    "accept_proposal",
    "correct",
    "forget",
    "reject_proposal",
    "remember",
}
LINUX_APPROVAL_BOUNDARY = "linux_polkit_rsa_sha256"
PROTOTYPE_APPROVAL_BOUNDARY = "terminal_prototype_same_uid_not_resistant"
OS_APPROVAL_UNAVAILABLE_BOUNDARY = "os_approval_unavailable"
GRANT_PREFIX = "rsa-sha256:"
MAX_BROKER_FRAME_BYTES = 65_536
MAX_GRANT_BYTES = 1024
MAX_CLOCK_SKEW_SECONDS = 5

POLKIT_HELPER_PATH = Path("/usr/libexec/continuum-memory/approval-helper")
POLKIT_POLICY_PATH = Path("/usr/share/polkit-1/actions/org.continuummemory.approval.policy")
PKEXEC_PATH = Path("/usr/bin/pkexec")
OPENSSL_PATH = Path("/usr/bin/openssl")
PUBLIC_KEY_DIRECTORY = Path("/etc/continuum-memory/approval-keys")
PRIVATE_KEY_DIRECTORY = Path("/var/lib/continuum-memory/approval-keys")

DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _vault_id(value: Any) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value) or not value.startswith("vlt_"):
        raise MemoryError("approval_invalid", "The approval vault identity is invalid.")
    return value


def _caller_uid(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MemoryError("approval_invalid", "The approval caller identity is invalid.")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise MemoryError("approval_invalid", "The approval digest is invalid.")
    return value


def _operation(value: Any) -> str:
    if value not in APPROVAL_OPERATIONS:
        raise MemoryError("approval_invalid", "The approval operation is invalid.")
    return value


def approval_payload(
    vault_id: str,
    caller_uid: int,
    nonce: str,
    operation: str,
    preview_digest: str,
    expires_at: int,
) -> bytes:
    _vault_id(vault_id)
    _caller_uid(caller_uid)
    if not isinstance(nonce, str) or not ID_RE.fullmatch(nonce):
        raise MemoryError("approval_invalid", "The approval nonce is invalid.")
    _operation(operation)
    _digest(preview_digest)
    if isinstance(expires_at, bool) or not isinstance(expires_at, int) or expires_at <= 0:
        raise MemoryError("approval_invalid", "The approval expiry is invalid.")
    value = {
        "caller_uid": caller_uid,
        "expires_at": expires_at,
        "nonce": nonce,
        "operation": operation,
        "preview_digest": preview_digest,
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "vault_id": vault_id,
    }
    return canonical_json(value).encode("utf-8")


def approval_request(challenge: Dict[str, Any], caller_uid: Optional[int] = None) -> Dict[str, Any]:
    expected = {"expires_at", "nonce", "operation", "preview", "preview_digest", "vault_id"}
    missing = sorted(expected - set(challenge))
    if missing:
        raise MemoryError("approval_invalid", "The approval challenge is incomplete.")
    preview = challenge["preview"]
    if not isinstance(preview, dict) or digest_json(preview) != challenge["preview_digest"]:
        raise MemoryError("approval_mismatch", "The approval preview digest does not match its content.")
    uid = os.getuid() if caller_uid is None else caller_uid
    request = {
        "action": "authorize",
        "caller_uid": uid,
        "expires_at": challenge["expires_at"],
        "nonce": challenge["nonce"],
        "operation": challenge["operation"],
        "preview": preview,
        "preview_digest": challenge["preview_digest"],
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "vault_id": challenge["vault_id"],
    }
    return validate_approval_request(request)


def validate_approval_request(value: Any, now: Optional[int] = None) -> Dict[str, Any]:
    required = {
        "action",
        "caller_uid",
        "expires_at",
        "nonce",
        "operation",
        "preview",
        "preview_digest",
        "schema_version",
        "vault_id",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise MemoryError("approval_invalid", "The approval request schema is invalid.")
    if value["schema_version"] != APPROVAL_SCHEMA_VERSION or value["action"] != "authorize":
        raise MemoryError("approval_invalid", "The approval request version or action is invalid.")
    approval_payload(
        _vault_id(value["vault_id"]),
        _caller_uid(value["caller_uid"]),
        value["nonce"],
        _operation(value["operation"]),
        _digest(value["preview_digest"]),
        value["expires_at"],
    )
    preview = value["preview"]
    if not isinstance(preview, dict) or digest_json(preview) != value["preview_digest"]:
        raise MemoryError("approval_mismatch", "The approval preview digest does not match its content.")
    current = int(time.time()) if now is None else now
    if value["expires_at"] < current:
        raise MemoryError("approval_expired", "The approval challenge expired.")
    if value["expires_at"] > current + GRANT_TTL_SECONDS + MAX_CLOCK_SKEW_SECONDS:
        raise MemoryError("approval_invalid", "The approval expiry exceeds the allowed lifetime.")
    encoded = canonical_json(value).encode("utf-8")
    if len(encoded) > MAX_BROKER_FRAME_BYTES:
        raise MemoryError("approval_invalid", "The approval request exceeds the size limit.")
    return value


def provision_request(vault_id: str, caller_uid: Optional[int] = None) -> Dict[str, Any]:
    uid = os.getuid() if caller_uid is None else caller_uid
    return {
        "action": "provision",
        "caller_uid": _caller_uid(uid),
        "schema_version": APPROVAL_SCHEMA_VERSION,
        "vault_id": _vault_id(vault_id),
    }


def validate_provision_request(value: Any) -> Dict[str, Any]:
    required = {"action", "caller_uid", "schema_version", "vault_id"}
    if not isinstance(value, dict) or set(value) != required:
        raise MemoryError("approval_invalid", "The provisioning request schema is invalid.")
    if value["schema_version"] != APPROVAL_SCHEMA_VERSION or value["action"] != "provision":
        raise MemoryError("approval_invalid", "The provisioning request version or action is invalid.")
    _caller_uid(value["caller_uid"])
    _vault_id(value["vault_id"])
    return value


def public_key_path(caller_uid: int) -> Path:
    return PUBLIC_KEY_DIRECTORY / ("uid-%d.pem" % _caller_uid(caller_uid))


def private_key_path(caller_uid: int) -> Path:
    return PRIVATE_KEY_DIRECTORY / ("uid-%d.pem" % _caller_uid(caller_uid))


def ensure_root_owned_regular(
    path: Path,
    label: str,
    executable: bool = False,
    private: bool = False,
) -> os.stat_result:
    if not path.is_absolute():
        raise MemoryError("approval_broker_unsafe", "%s path is not absolute." % label)
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError as error:
            raise MemoryError("approval_broker_unavailable", "%s path is missing." % label) from error
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise MemoryError("approval_broker_unsafe", "%s has an unsafe ancestor." % label)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise MemoryError("approval_broker_unsafe", "%s has an untrusted ancestor." % label)
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise MemoryError("approval_broker_unavailable", "%s is missing." % label) from error
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
        raise MemoryError("approval_broker_unsafe", "%s must be one regular file." % label)
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise MemoryError("approval_broker_unsafe", "%s is not protected by root ownership." % label)
    if executable and not info.st_mode & stat.S_IXUSR:
        raise MemoryError("approval_broker_unsafe", "%s is not executable." % label)
    if private and info.st_mode & 0o077:
        raise MemoryError("approval_broker_unsafe", "%s is not root-only." % label)
    return info


def linux_public_key(caller_uid: int) -> Optional[Path]:
    if not sys.platform.startswith("linux"):
        return None
    path = public_key_path(caller_uid)
    if not path_exists(path):
        return None
    ensure_root_owned_regular(path, "The Linux approval public key")
    return path


def encode_grant(signature: bytes) -> str:
    return GRANT_PREFIX + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def decode_grant(grant: str) -> bytes:
    if not isinstance(grant, str) or not grant.startswith(GRANT_PREFIX):
        raise MemoryError("approval_invalid", "The approval grant format is invalid.")
    encoded = grant[len(GRANT_PREFIX) :]
    if not encoded or len(grant.encode("ascii", "ignore")) > MAX_GRANT_BYTES:
        raise MemoryError("approval_invalid", "The approval grant size is invalid.")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
        raise MemoryError("approval_invalid", "The approval grant encoding is invalid.")
    try:
        return base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise MemoryError("approval_invalid", "The approval grant encoding is invalid.") from error


def _openssl_environment() -> Dict[str, str]:
    return {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


def sign_payload(
    private_key: Path,
    payload: bytes,
    openssl_path: Path = OPENSSL_PATH,
    key_validator: Callable[[Path, str], Any] = lambda path, label: ensure_root_owned_regular(
        path, label, private=True
    ),
) -> str:
    key_validator(private_key, "The Linux approval private key")
    ensure_root_owned_regular(openssl_path, "The OpenSSL executable", executable=True)
    try:
        result = subprocess.run(
            [str(openssl_path), "dgst", "-sha256", "-sign", str(private_key)],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            env=_openssl_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MemoryError("approval_broker_unavailable", "The approval signer is unavailable.") from error
    if result.returncode != 0 or not result.stdout:
        raise MemoryError("approval_broker_unavailable", "The approval signer failed.")
    return encode_grant(result.stdout)


def verify_payload(
    public_key: Path,
    payload: bytes,
    grant: str,
    openssl_path: Path = OPENSSL_PATH,
    key_validator: Callable[[Path, str], Any] = ensure_root_owned_regular,
) -> bool:
    key_validator(public_key, "The Linux approval public key")
    ensure_root_owned_regular(openssl_path, "The OpenSSL executable", executable=True)
    signature = decode_grant(grant)
    with tempfile.NamedTemporaryFile(prefix="continuum-approval-signature-") as signature_file:
        signature_file.write(signature)
        signature_file.flush()
        try:
            result = subprocess.run(
                [
                    str(openssl_path),
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(public_key),
                    "-signature",
                    signature_file.name,
                ],
                input=payload,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
                env=_openssl_environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise MemoryError(
                "approval_broker_unavailable", "The approval verifier is unavailable."
            ) from error
    return result.returncode == 0
