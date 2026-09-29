"""Immutable initialization records: workflow evidence, never owner authority.

Interrupted attempts reserve their directory permanently. These records are not
an anti-rollback boundary, and their file flushes do not claim power-loss safety.
"""

from pathlib import Path
from typing import Dict, Optional

from .errors import MemoryError
from .security import (
    bounded_id,
    canonical_json,
    ensure_private_directory,
    path_exists,
    read_private,
    write_private,
)
from .transport import decode_frame

MAX_RECORD_BYTES = 1024


def initialization_paths(data_dir: Path) -> Dict[str, Path]:
    return {
        "bootstrap_claim": data_dir / "bootstrap.claim",
        "bootstrap_complete": data_dir / "bootstrap.complete",
    }


def _incomplete() -> MemoryError:
    return MemoryError(
        "initialization_incomplete",
        "Initialization is incomplete or inconsistent. Preserve this home and use a fresh location.",
    )


def _vault_id(value: object) -> str:
    value = bounded_id(value, "vault_id")
    if not value.startswith("vlt_"):
        raise _incomplete()
    return value


def _record(path: Path, kind: str) -> str:
    value = decode_frame(read_private(path, MAX_RECORD_BYTES))
    if (not isinstance(value, dict) or set(value) != {"version", "kind", "vault_id"}
            or type(value["version"]) is not int or value["version"] != 1
            or value["kind"] != kind):
        raise _incomplete()
    return _vault_id(value["vault_id"])


def _encoded(kind: str, vault_id: str) -> bytes:
    return (canonical_json({"version": 1, "kind": kind, "vault_id": _vault_id(vault_id)})
            + "\n").encode("utf-8")


def read_initialization_state(data_dir: Path) -> Optional[str]:
    """Return a completed identity, or None for a *candidate* legacy home.

    None alone never establishes legacy status: the same guarded database
    connection must also validate its identity, schema and absent protocol flag.
    A visible claim is never stolen, repaired, or adopted by another initializer.
    """
    files = initialization_paths(data_dir)
    try:
        ensure_private_directory(data_dir)
        claim_exists = path_exists(files["bootstrap_claim"])
        complete_exists = path_exists(files["bootstrap_complete"])
        if not claim_exists and not complete_exists:
            return None
        if not claim_exists or not complete_exists:
            raise _incomplete()
        vault_id = _record(files["bootstrap_claim"], "claim")
        if _record(files["bootstrap_complete"], "complete") != vault_id:
            raise _incomplete()
        return vault_id
    except (MemoryError, OSError, ValueError, TypeError, RecursionError):
        raise _incomplete() from None


def claim_initialization(data_dir: Path, vault_id: str) -> None:
    """Exclusively reserve an attempt before any key, capability or DB write."""
    try:
        write_private(initialization_paths(data_dir)["bootstrap_claim"], _encoded("claim", vault_id))
    except FileExistsError:
        raise MemoryError("already_initialized", "The selected Continuum home is already initialized.") from None
    except (MemoryError, OSError, ValueError, TypeError):
        # A short/failed write may have reserved the path. Never remove it.
        raise _incomplete() from None


def complete_initialization(data_dir: Path, vault_id: str) -> None:
    """Publish once, only after the caller has verified and closed the vault."""
    files = initialization_paths(data_dir)
    try:
        if _record(files["bootstrap_claim"], "claim") != _vault_id(vault_id):
            raise _incomplete()
        write_private(files["bootstrap_complete"], _encoded("complete", vault_id))
        if read_initialization_state(data_dir) != vault_id:
            raise _incomplete()
    except (MemoryError, OSError, ValueError, TypeError, RecursionError):
        # A complete record may already be visible after a lost reply. Inspect
        # the home normally; this function must never overwrite/adopt a record.
        raise _incomplete() from None


def require_initialization_metadata(protocol: Optional[str], vault_id: Optional[str],
                                    marker_vault_id: Optional[str]) -> None:
    """Bind filesystem completion to transactional DB state before admission."""
    if protocol is None and marker_vault_id is None:
        return
    if protocol != "1" or marker_vault_id is None or vault_id != marker_vault_id:
        raise _incomplete()
