"""Wire limits shared by local transports; no kernel or storage concurrency."""

import json
from typing import Any

from .security import MAX_FRAME_BYTES

READ_TIMEOUT = 2.0
WRITE_TIMEOUT = 2.0
CLIENT_TIMEOUT = 5.0
MAX_CONNECTIONS = 16
CHUNK_BYTES = 8192
MAX_ID_BYTES = 128
MAX_JSON_DEPTH = 64


def valid_id(value: Any) -> bool:
    if isinstance(value, str):
        from .admission import contains_secret
        try:
            return len(value.encode("utf-8")) <= MAX_ID_BYTES and not contains_secret(value)
        except UnicodeError:
            return False
    return isinstance(value, int) and not isinstance(value, bool) and -(2**63) <= value < 2**63


def valid_method(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 64


def _reject_constant(_value: str) -> None:
    raise ValueError("Invalid JSON constant")


def _unique_object(pairs: Any) -> Any:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def decode_frame(raw: bytes) -> Any:
    # Callers cap raw acquisition before parsing. Reject ambiguous JSON too.
    text = raw.decode("utf-8")
    # Do not depend on an interpreter's recursion threshold or allocate a deeply
    # nested object graph first. Quoted/escaped delimiters are plain string data.
    depth, quoted, escaped = 0, False, False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON nesting exceeds limit")
        elif character in "]}":
            depth -= 1
    return json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_unique_object)


def encode_frame(value: Any) -> bytes:
    """Bound the serialized frame, including its LF, before handing it to I/O."""
    encoded = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    for part in encoder.iterencode(value):
        piece = part.encode("utf-8")
        if len(encoded) + len(piece) >= MAX_FRAME_BYTES:
            raise ValueError("Frame exceeds limit")
        encoded.extend(piece)
    encoded.extend(b"\n")
    return bytes(encoded)
