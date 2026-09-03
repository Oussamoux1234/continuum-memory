"""Replaceable human-presence broker boundary.

The prototype implementation signs with the control capability after an interactive TTY
confirmation. A trustworthy Linux implementation replaces this class with a polkit-backed
signer whose authority key is unavailable to the CLI and agent-facing processes.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, Protocol

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
