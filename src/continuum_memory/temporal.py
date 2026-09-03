"""Strict, comparable UTC timestamps for retention and valid-time fields."""

import re
from datetime import date, datetime, timedelta, timezone

from .errors import invalid


DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
DATETIME_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$"
)


def canonical_utc(value: str, field: str) -> str:
    """Validate the supported ISO/RFC 3339 subset and normalize it to UTC."""
    if DATE_RE.fullmatch(value):
        try:
            parsed_date = date.fromisoformat(value)
        except ValueError as exc:
            raise invalid("Date/time value is invalid.", field) from exc
        parsed = datetime(
            parsed_date.year,
            parsed_date.month,
            parsed_date.day,
            tzinfo=timezone.utc,
        )
    else:
        match = DATETIME_RE.fullmatch(value)
        if not match:
            raise invalid("Expected YYYY-MM-DD or a timezone-aware RFC 3339 timestamp.", field)
        offset = match.group(6)
        if offset == "-00:00":
            raise invalid("Unknown local offsets are not accepted.", field)
        if offset != "Z":
            offset_hours = int(offset[1:3])
            offset_minutes = int(offset[4:6])
            if offset_minutes > 59 or offset_hours > 14 or (offset_hours == 14 and offset_minutes != 0):
                raise invalid("UTC offset is outside the supported range.", field)
        try:
            parsed_date = date.fromisoformat(match.group(1))
            fraction = (match.group(5) or "").ljust(6, "0")
            if offset == "Z":
                zone = timezone.utc
            else:
                direction = 1 if offset[0] == "+" else -1
                delta = timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))
                zone = timezone(direction * delta)
            parsed = datetime(
                parsed_date.year,
                parsed_date.month,
                parsed_date.day,
                int(match.group(2)),
                int(match.group(3)),
                int(match.group(4)),
                int(fraction or "0"),
                zone,
            )
            parsed = parsed.astimezone(timezone.utc)
        except (OverflowError, ValueError) as exc:
            raise invalid("Date/time value is invalid.", field) from exc
    return _fixed_utc(parsed)


def datetime_utc(value: datetime) -> datetime:
    """Require an aware clock value and return it in UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock provider must return a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def format_utc(value: datetime) -> str:
    return _fixed_utc(datetime_utc(value))


def _fixed_utc(value: datetime) -> str:
    return "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ" % (
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond,
    )
