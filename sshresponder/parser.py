"""Parse sshd authentication events out of /var/log/auth.log style files."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, Optional, Union

from .models import AuthEvent

# Supports the classic syslog prefix ("Oct 15 02:14:03") and the ISO-8601 prefix
# newer rsyslog/journald setups use ("2026-10-15T02:14:03.123456+04:00").
_PREFIX = (
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+sshd(?:-session)?(?:\[\d+\])?:\s+"
)

_FAILED = re.compile(
    _PREFIX + r"Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    _PREFIX + r"Accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
)


def _parse_timestamp(raw: str, year: int) -> datetime:
    if raw[0].isdigit():  # ISO 8601
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw).replace(tzinfo=None)
    # Classic syslog has no year, so the caller supplies one.
    normalised = " ".join(raw.split())  # "Oct  5" -> "Oct 5"
    return datetime.strptime(f"{year} {normalised}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, year: int) -> Optional[AuthEvent]:
    """Return an AuthEvent for a failed/accepted login line, or None for anything else."""
    match = _FAILED.match(line)
    outcome = "failed"
    if match is None:
        match = _ACCEPTED.match(line)
        outcome = "accepted"
    if match is None:
        return None

    method = match.group("method")
    if method == "none":  # pre-auth probing, not a real credential attempt
        return None

    try:
        ip = str(ipaddress.ip_address(match.group("ip")))
        timestamp = _parse_timestamp(match.group("ts"), year)
    except ValueError:
        return None  # malformed IP or timestamp: skip the line rather than crash

    return AuthEvent(
        timestamp=timestamp,
        host=match.group("host"),
        outcome=outcome,
        method=method,
        user=match.group("user"),
        ip=ip,
        port=int(match.group("port")),
        invalid_user=bool(match.groupdict().get("invalid")),
    )


def parse_lines(lines: Iterable[str], year: int) -> Iterator[AuthEvent]:
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            yield event


def parse_file(path: Union[str, Path], year: int) -> Iterator[AuthEvent]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        yield from parse_lines(handle, year)
