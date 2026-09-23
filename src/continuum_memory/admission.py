"""Local, deterministic admission checks; not a universal secret/PII detector."""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, Iterable, Tuple

from .errors import MemoryError
from .security import MAX_BODY_BYTES, bounded_text, ensure_private_regular, path_exists, read_private
from .transport import decode_frame

POLICY_FILE = "admission-policy.json"
MAX_POLICY_BYTES = 16384
MAX_POLICY_ENTRIES = 32

# Fixed expressions over bounded fields. No operator-supplied regular expressions,
# entropy guesses, network calls, or decoding of arbitrary embedded material.
_PATTERNS = tuple(re.compile(pattern) for pattern in (
    r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----",
    r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])",
    r"(?<![A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{30,}(?![A-Za-z0-9])",
    r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}",
    r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}",
    r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{20,}",
    r"(?<![A-Za-z0-9_])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}",
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*",
    r"(?i)\bauthorization\s*:\s*basic\s+[A-Za-z0-9+/]{16,}={0,2}",
    r"[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s/:@<>]{1,64}:[A-Za-z0-9_~.!$%&*+=?:-]{8,}@",
))
_ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|secret[_-]?key)"
    r"\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_./+~!@#$%^&*=:-]{12,})"
)


def contains_secret(value: str) -> bool:
    if any(pattern.search(value) for pattern in _PATTERNS):
        return True
    # Context-qualified assignments need both letters and digits. Short passwords,
    # prose-only passphrases, unknown formats and obfuscation are explicit limits.
    return any(re.search(r"[A-Za-z]", match[1]) and re.search(r"[0-9]", match[1])
               for match in _ASSIGNMENT.finditer(value))


@dataclass(frozen=True)
class AdmissionPolicy:
    deny_literals: Tuple[str, ...] = ()
    allow_sha256: FrozenSet[str] = frozenset()

    @classmethod
    def load(cls, data_dir: Path) -> "AdmissionPolicy":
        path = data_dir / POLICY_FILE
        if not path_exists(path):
            return cls()
        try:
            # Reject FIFOs/devices before open; read_private repeats validation on
            # the descriptor and rejects symlinks/hardlinks and oversized reads.
            ensure_private_regular(path, "Admission policy")
            value = decode_frame(read_private(path, MAX_POLICY_BYTES))
            if (not isinstance(value, dict) or set(value) - {"version", "deny_literals", "allow_sha256"}
                    or type(value.get("version")) is not int or value["version"] != 1):
                raise ValueError
            denies = value.get("deny_literals", [])
            allows = value.get("allow_sha256", [])
            for entries in (denies, allows):
                if (not isinstance(entries, list) or len(entries) > MAX_POLICY_ENTRIES
                        or not all(isinstance(item, str) for item in entries) or len(set(entries)) != len(entries)):
                    raise ValueError
            for literal in denies:
                bounded_text(literal, "policy", 128)
                if len(literal.encode("utf-8")) < 4:
                    raise ValueError
            if any(re.fullmatch(r"[0-9a-f]{64}", digest) is None for digest in allows):
                raise ValueError
            return cls(tuple(denies), frozenset(allows))
        except (MemoryError, ValueError, TypeError, UnicodeError, RecursionError):
            # Never retain parser diagnostics, field names, paths, or policy text.
            raise MemoryError("admission_policy_invalid", "The local admission policy is invalid or unsafe.") from None

    def check(self, values: Iterable[str]) -> None:
        for value in values:
            bounded_text(value, "content", MAX_BODY_BYTES, allow_empty=True)
            if self.allow_sha256 and hashlib.sha256(value.encode("utf-8")).hexdigest() in self.allow_sha256:
                continue
            if contains_secret(value) or any(literal in value for literal in self.deny_literals):
                raise MemoryError("secret_rejected", "Potential secret or prohibited content was rejected before persistence.")
