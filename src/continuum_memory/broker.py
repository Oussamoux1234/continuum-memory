"""Replaceable human-presence broker boundary."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Protocol

from .approval import (
    LINUX_APPROVAL_BOUNDARY,
    MAX_BROKER_FRAME_BYTES,
    PKEXEC_PATH,
    POLKIT_HELPER_PATH,
    approval_request,
    decode_grant,
    ensure_root_owned_regular,
    provision_request,
)
from .errors import MemoryError
from .security import sign_grant
from .storage import load_capability


class ApprovalBroker(Protocol):
    def authorize(self, challenge: Dict[str, Any]) -> str:
        """Return a grant bound to the supplied canonical challenge, or fail closed."""


class TerminalApprovalBroker:
    def __init__(self, control_capability_file: Path):
        self.control_capability_file = control_capability_file

    def authorize(self, challenge: Dict[str, Any]) -> str:
        print(json.dumps(challenge["preview"], ensure_ascii=False, indent=2, sort_keys=True))
        print("\n%s" % challenge["confirmation"])
        print("Warning: this prototype confirmation does not resist a shell-capable same-UID agent.")
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise MemoryError("interactive_required", "Administrative confirmation requires an interactive terminal.")
        expected = "ACCEPT %s" % challenge["preview_digest"][:12]
        entered = input("> ")
        if entered != expected:
            raise MemoryError("cancelled", "The administrative operation was not confirmed.")
        capability = load_capability(self.control_capability_file)
        return sign_grant(
            capability["token"].encode("ascii"),
            challenge["nonce"],
            challenge["operation"],
            challenge["preview_digest"],
        )


class LinuxPolkitApprovalBroker:
    """Invoke a fixed root-owned helper; request content travels only over stdin."""

    def __init__(
        self,
        helper_path: Path = POLKIT_HELPER_PATH,
        pkexec_path: Path = PKEXEC_PATH,
        runner: Callable[..., Any] = subprocess.run,
        path_validator: Callable[..., Any] = ensure_root_owned_regular,
        caller_uid: Any = None,
    ):
        self.helper_path = helper_path
        self.pkexec_path = pkexec_path
        self.runner = runner
        self.path_validator = path_validator
        self.caller_uid = os.getuid() if caller_uid is None else caller_uid

    def _invoke(self, action: str, request: Dict[str, Any], timeout: int) -> Dict[str, Any]:
        self.path_validator(self.pkexec_path, "The pkexec executable", executable=True)
        self.path_validator(self.helper_path, "The Continuum approval helper", executable=True)
        encoded = (json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        if len(encoded) > MAX_BROKER_FRAME_BYTES:
            raise MemoryError("approval_invalid", "The approval broker request exceeds the size limit.")
        try:
            result = self.runner(
                [str(self.pkexec_path), str(self.helper_path), action],
                input=encoded,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            )
        except subprocess.TimeoutExpired as error:
            raise MemoryError("approval_expired", "The operating-system approval timed out.") from error
        except OSError as error:
            raise MemoryError(
                "approval_broker_unavailable", "The operating-system approval broker is unavailable."
            ) from error
        if result.returncode == 126:
            raise MemoryError("cancelled", "The operating-system approval was cancelled.")
        if result.returncode != 0:
            raise MemoryError("approval_broker_unavailable", "The operating-system approval failed closed.")
        output = result.stdout.encode("utf-8") if isinstance(result.stdout, str) else result.stdout
        if not output or len(output) > MAX_BROKER_FRAME_BYTES:
            raise MemoryError("approval_invalid", "The operating-system approval response is invalid.")
        try:
            value = json.loads(output.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise MemoryError("approval_invalid", "The operating-system approval response is malformed.") from error
        if not isinstance(value, dict):
            raise MemoryError("approval_invalid", "The operating-system approval response is invalid.")
        return value

    def authorize(self, challenge: Dict[str, Any]) -> str:
        if challenge.get("approval_boundary") != LINUX_APPROVAL_BOUNDARY:
            raise MemoryError("approval_invalid", "The challenge does not require the Linux approval broker.")
        request = approval_request(challenge, self.caller_uid)
        remaining = request["expires_at"] - int(time.time()) + 1
        result = self._invoke("authorize", request, max(1, min(remaining, 125)))
        if set(result) != {"grant", "schema_version"} or result.get("schema_version") != 1:
            raise MemoryError("approval_invalid", "The operating-system approval response schema is invalid.")
        grant = result.get("grant")
        decode_grant(grant)
        return grant

    def provision(self, vault_id: str) -> Dict[str, Any]:
        if not sys.platform.startswith("linux"):
            raise MemoryError("unsupported_platform", "Linux polkit provisioning requires Linux.")
        request = provision_request(vault_id, self.caller_uid)
        result = self._invoke("provision", request, 125)
        if set(result) != {"status", "vault_id"}:
            raise MemoryError("approval_invalid", "The provisioning response schema is invalid.")
        if result.get("status") not in {"provisioned", "already_provisioned"}:
            raise MemoryError("approval_invalid", "The provisioning response status is invalid.")
        if result.get("vault_id") != vault_id:
            raise MemoryError("approval_invalid", "The provisioning response vault does not match.")
        return result


def broker_for_challenge(challenge: Dict[str, Any], control_capability_file: Path) -> ApprovalBroker:
    if challenge.get("approval_boundary") == LINUX_APPROVAL_BOUNDARY:
        return LinuxPolkitApprovalBroker()
    return TerminalApprovalBroker(control_capability_file)
