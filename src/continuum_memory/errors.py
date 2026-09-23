"""Stable, content-free errors shared by every surface."""

from typing import Any, Dict, Optional


class MemoryError(Exception):
    def __init__(self, code: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def as_dict(self) -> Dict[str, Any]:
        result = {"code": self.code, "message": self.message}
        if self.details:
            result["details"] = self.details
        return result


class CommittedAuditError(MemoryError):
    """SQLite committed; a later audit-anchor operation did not complete."""

    def __init__(self):
        super().__init__(
            "committed_audit_degraded",
            "A transaction committed but audit synchronization failed. Check the operation result before retrying.",
        )


def invalid(message: str, field: Optional[str] = None) -> MemoryError:
    details = {"field": field} if field else None
    return MemoryError("invalid_request", message, details)


NOT_FOUND = MemoryError("not_found", "The requested item is unavailable in this scope.")
UNAVAILABLE = MemoryError("unavailable", "The local memory service is unavailable.")
