"""Content-free receipt selectors, never approval or capability authority."""

from .errors import MemoryError, invalid
from .security import bounded_id


def validate_locator(value):
    """Return a bounded, canonical v1 descriptor without echoing invalid input."""
    message = "The recovery locator is invalid."
    if not isinstance(value, dict) or set(value) != {"version", "vault_id", "nonce", "binding"}:
        raise invalid(message)
    if type(value["version"]) is not int or value["version"] != 1:
        raise invalid(message)
    try:
        vault_id = bounded_id(value["vault_id"], "vault_id")
        nonce = bounded_id(value["nonce"], "nonce")
    except MemoryError:
        raise invalid(message) from None
    binding = value["binding"]
    if (not isinstance(binding, str) or len(binding) != 64
            or any(character not in "0123456789abcdef" for character in binding)):
        raise invalid(message)
    return {"version": 1, "vault_id": vault_id, "nonce": nonce, "binding": binding}
