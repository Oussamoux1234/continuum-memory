"""Root-side Linux approval helper. Install only at a root-owned system path."""

import argparse
import fcntl
import json
import os
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ElementTree
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, Optional, TextIO

from .approval import (
    MAX_BROKER_FRAME_BYTES,
    OPENSSL_PATH,
    POLKIT_HELPER_PATH,
    POLKIT_POLICY_PATH,
    approval_payload,
    ensure_root_owned_regular,
    private_key_path,
    public_key_path,
    sign_payload,
    validate_approval_request,
    validate_provision_request,
    verify_payload,
)
from .errors import MemoryError
from .security import canonical_json, path_exists


MAX_POLICY_BYTES = 65_536
PROVISION_LOCK_NAME = ".provision.lock"


def _root_directory(path: Path, private: bool) -> None:
    path.mkdir(mode=0o700 if private else 0o755, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
        raise MemoryError("approval_broker_unsafe", "An approval key directory is unsafe.")
    if info.st_mode & (0o077 if private else 0o022):
        raise MemoryError("approval_broker_unsafe", "An approval key directory is writable by an untrusted user.")
    os.chmod(str(path), 0o700 if private else 0o755)


@contextmanager
def _provision_lock(path: Path, expected_owner: int = 0) -> Iterator[None]:
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags, 0o600)
    except OSError as error:
        raise MemoryError("approval_broker_unsafe", "The approval provisioning lock is unsafe.") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != expected_owner
            or info.st_mode & 0o077
        ):
            raise MemoryError("approval_broker_unsafe", "The approval provisioning lock is unsafe.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as error:
            raise MemoryError(
                "approval_broker_unavailable", "Approval key provisioning could not be serialized."
            ) from error
        yield
    finally:
        os.close(descriptor)


def validate_installed_policy(
    path: Path = POLKIT_POLICY_PATH,
    path_validator: Callable[..., Any] = ensure_root_owned_regular,
) -> None:
    path_validator(path, "The Continuum approval polkit policy")
    try:
        encoded = path.read_bytes()
    except OSError as error:
        raise MemoryError("approval_broker_unavailable", "The approval policy could not be read.") from error
    if not encoded or len(encoded) > MAX_POLICY_BYTES:
        raise MemoryError("approval_broker_unsafe", "The approval policy size is invalid.")
    try:
        root = ElementTree.fromstring(encoded)
    except ElementTree.ParseError as error:
        raise MemoryError("approval_broker_unsafe", "The approval policy is malformed.") from error
    actions = root.findall("./action") if root.tag == "policyconfig" else []
    if len(actions) != 1 or actions[0].get("id") != "org.continuummemory.approval":
        raise MemoryError("approval_broker_unsafe", "The approval policy action is invalid.")
    action = actions[0]
    defaults = action.findall("./defaults")
    expected_defaults = {"allow_any": "no", "allow_inactive": "no", "allow_active": "auth_admin"}
    if len(defaults) != 1:
        raise MemoryError("approval_broker_unsafe", "The approval policy defaults are invalid.")
    for name, expected in expected_defaults.items():
        values = defaults[0].findall("./%s" % name)
        if len(values) != 1 or (values[0].text or "").strip() != expected:
            raise MemoryError("approval_broker_unsafe", "The approval policy defaults are invalid.")
    annotations = [
        item
        for item in action.findall("./annotate")
        if item.get("key") == "org.freedesktop.policykit.exec.path"
    ]
    if len(annotations) != 1 or (annotations[0].text or "").strip() != str(POLKIT_HELPER_PATH):
        raise MemoryError("approval_broker_unsafe", "The approval policy helper path is invalid.")


def _sync_file(path: Path) -> None:
    descriptor = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _run_openssl(arguments: Any) -> None:
    ensure_root_owned_regular(OPENSSL_PATH, "The OpenSSL executable", executable=True)
    try:
        result = subprocess.run(
            [str(OPENSSL_PATH)] + list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MemoryError("approval_broker_unavailable", "OpenSSL is unavailable.") from error
    if result.returncode != 0:
        raise MemoryError("approval_broker_unavailable", "OpenSSL could not create approval keys.")


def provision_keys(caller_uid: int) -> Dict[str, Any]:
    previous_umask = os.umask(0o022)
    try:
        private_path = private_key_path(caller_uid)
        public_path = public_key_path(caller_uid)
        _root_directory(private_path.parent, private=True)
        _root_directory(public_path.parent, private=False)
        with _provision_lock(private_path.parent / PROVISION_LOCK_NAME):
            return _provision_keys_locked(private_path, public_path)
    finally:
        os.umask(previous_umask)


def _verify_key_pair(private_path: Path, public_path: Path) -> None:
    ensure_root_owned_regular(private_path, "The Linux approval private key", private=True)
    ensure_root_owned_regular(public_path, "The Linux approval public key")
    probe = b"continuum-memory approval key pair check"
    grant = sign_payload(private_path, probe)
    if not verify_payload(public_path, probe, grant):
        raise MemoryError("approval_broker_unsafe", "The installed approval key pair does not match.")


def _provision_keys_locked(private_path: Path, public_path: Path) -> Dict[str, Any]:
    private_exists = path_exists(private_path)
    public_exists = path_exists(public_path)
    if private_exists or public_exists:
        if not private_exists or not public_exists:
            raise MemoryError("approval_broker_unsafe", "Approval key provisioning is incomplete.")
        _verify_key_pair(private_path, public_path)
        return {"status": "already_provisioned"}

    previous_umask = os.umask(0o077)
    private_temporary: Optional[Path] = None
    public_temporary: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".approval-private-", dir=str(private_path.parent), delete=False
        ) as handle:
            private_temporary = Path(handle.name)
        with tempfile.NamedTemporaryFile(
            prefix=".approval-public-", dir=str(public_path.parent), delete=False
        ) as handle:
            public_temporary = Path(handle.name)
        _run_openssl(
            [
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:3072",
                "-out",
                str(private_temporary),
            ]
        )
        _run_openssl(
            [
                "pkey",
                "-in",
                str(private_temporary),
                "-pubout",
                "-out",
                str(public_temporary),
            ]
        )
        os.chmod(str(private_temporary), 0o600)
        os.chmod(str(public_temporary), 0o644)
        _sync_file(private_temporary)
        _sync_file(public_temporary)
        os.replace(str(private_temporary), str(private_path))
        private_temporary = None
        os.replace(str(public_temporary), str(public_path))
        public_temporary = None
        _sync_directory(private_path.parent)
        _sync_directory(public_path.parent)
        _verify_key_pair(private_path, public_path)
        return {"status": "provisioned"}
    finally:
        os.umask(previous_umask)
        for temporary in (private_temporary, public_temporary):
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass


def render_preview(preview: Dict[str, Any]) -> str:
    """Render untrusted preview text without terminal-active Unicode controls."""
    return json.dumps(preview, ensure_ascii=True, indent=2, sort_keys=True)


def _tty_confirmation(request: Dict[str, Any]) -> bool:
    try:
        with open("/dev/tty", "r+", encoding="utf-8") as terminal:
            terminal.write(render_preview(request["preview"]))
            terminal.write("\n\nOS authorization succeeded. Confirm exact digest %s.\n" % request["preview_digest"])
            terminal.write("Type ACCEPT %s to continue: " % request["preview_digest"][:12])
            terminal.flush()
            entered = terminal.readline().rstrip("\r\n")
    except OSError as error:
        raise MemoryError(
            "interactive_required", "The privileged approval helper requires a controlling terminal."
        ) from error
    return entered == "ACCEPT %s" % request["preview_digest"][:12]


def _sign_for_caller(caller_uid: int, payload: bytes) -> str:
    return sign_payload(private_key_path(caller_uid), payload)


def authorize_request(
    value: Any,
    authenticated_uid: int,
    confirmer: Callable[[Dict[str, Any]], bool] = _tty_confirmation,
    signer: Callable[[int, bytes], str] = _sign_for_caller,
) -> Dict[str, Any]:
    request = validate_approval_request(value)
    if request["caller_uid"] != authenticated_uid:
        raise MemoryError("approval_invalid", "The authenticated caller does not match the request.")
    if not confirmer(request):
        raise MemoryError("cancelled", "The administrative operation was not confirmed.")
    payload = approval_payload(
        request["vault_id"],
        request["caller_uid"],
        request["nonce"],
        request["operation"],
        request["preview_digest"],
        request["expires_at"],
    )
    grant = signer(request["caller_uid"], payload)
    return {"grant": grant, "schema_version": 1}


def _read_request(stream: TextIO) -> Dict[str, Any]:
    raw = stream.buffer.read(MAX_BROKER_FRAME_BYTES + 1)  # type: ignore[attr-defined]
    if not raw or len(raw) > MAX_BROKER_FRAME_BYTES:
        raise MemoryError("approval_invalid", "The approval helper request size is invalid.")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise MemoryError("approval_invalid", "The approval helper request is malformed.") from error
    if not isinstance(value, dict):
        raise MemoryError("approval_invalid", "The approval helper request must be an object.")
    return value


def _authenticated_uid() -> int:
    value = os.environ.get("PKEXEC_UID")
    if value is None or not value.isdigit():
        raise MemoryError("approval_invalid", "The helper was not invoked by pkexec.")
    return int(value)


def _ensure_privileged_runtime() -> None:
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise MemoryError("approval_broker_unsafe", "The approval helper requires Linux root execution.")
    ensure_root_owned_regular(Path(__file__), "The installed approval helper module")
    validate_installed_policy()


def main(argv: Any = None) -> int:
    parser = argparse.ArgumentParser(
        prog="continuum-polkit-helper",
        description="Privileged Continuum Memory approval signer",
    )
    parser.add_argument("action", choices=["authorize", "provision"])
    args = parser.parse_args(argv)
    try:
        _ensure_privileged_runtime()
        request = _read_request(sys.stdin)
        authenticated_uid = _authenticated_uid()
        if args.action == "authorize":
            result = authorize_request(request, authenticated_uid)
        else:
            provision = validate_provision_request(request)
            if provision["caller_uid"] != authenticated_uid:
                raise MemoryError("approval_invalid", "The authenticated caller does not match the request.")
            result = provision_keys(authenticated_uid)
            result["vault_id"] = provision["vault_id"]
        print(canonical_json(result))
        return 0
    except MemoryError as error:
        print(canonical_json({"error": error.as_dict()}), file=sys.stderr)
        return 126 if error.code == "cancelled" else 2


if __name__ == "__main__":
    raise SystemExit(main())
