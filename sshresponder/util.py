"""Small helpers: network classification and safe display of untrusted text."""

from __future__ import annotations

import ipaddress
from typing import Iterable, List, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Addresses that must never be auto-blocked or sent to an external service.
_INTERNAL_RANGES = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)
INTERNAL_NETWORKS: List[IPNetwork] = [ipaddress.ip_network(n) for n in _INTERNAL_RANGES]


def _normalise(ip: str):
    addr = ipaddress.ip_address(ip)
    if addr.version == 6 and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped  # ::ffff:10.0.0.1 is really 10.0.0.1
    return addr


def is_internal(ip: str) -> bool:
    """True for private, loopback, link-local and other non-routable addresses."""
    addr = _normalise(ip)
    if addr.is_multicast or addr.is_unspecified:
        return True
    return any(addr in network for network in INTERNAL_NETWORKS)


def parse_allowlist(values: Iterable[str]) -> List[IPNetwork]:
    """Turn ['203.0.113.7', '198.51.100.0/24'] into network objects (blank entries are ignored)."""
    networks: List[IPNetwork] = []
    for value in values:
        value = value.strip()
        if value:
            networks.append(ipaddress.ip_network(value, strict=False))
    return networks


def is_allowlisted(ip: str, networks: Iterable[IPNetwork]) -> bool:
    addr = _normalise(ip)
    return any(addr in network for network in networks)


def sanitize(text: object, max_len: int = 32) -> str:
    """Make attacker-controlled text safe to print or post.

    Usernames come straight from the log, so an attacker can put terminal escape
    codes, newlines or markdown in them. Replace anything unprintable and the
    backtick, and cap the length.
    """
    cleaned = "".join(ch if ch.isprintable() and ch != "`" else "?" for ch in str(text))
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 1] + "…"
    return cleaned
