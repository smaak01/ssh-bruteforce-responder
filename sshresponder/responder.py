"""Containment: decide whether to block an attacker and (only if asked) do it."""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, List

from .models import Incident
from .scoring import severity_at_least
from .util import IPNetwork, is_allowlisted, is_internal

SUPPORTED_FIREWALLS = ("ufw", "iptables")


@dataclass
class ResponsePolicy:
    block_min_severity: str = "high"
    firewall: str = "ufw"
    port: int = 22
    enforce: bool = False  # default is dry-run: print the command, change nothing
    allowlist: List[IPNetwork] = field(default_factory=list)


def build_block_command(ip: str, firewall: str = "ufw", port: int = 22) -> List[str]:
    """Build the firewall command as an argument list (never a shell string).

    ``ipaddress.ip_address`` rejects anything that isn't a plain IP, so log
    content can never smuggle extra arguments or shell syntax into the command.
    """
    addr = ipaddress.ip_address(ip)  # raises ValueError on anything else
    if not 1 <= port <= 65535:
        raise ValueError(f"invalid port: {port}")

    if firewall == "ufw":
        return ["ufw", "deny", "from", str(addr), "to", "any", "port", str(port), "proto", "tcp"]
    if firewall == "iptables":
        binary = "ip6tables" if addr.version == 6 else "iptables"
        return [binary, "-I", "INPUT", "-s", str(addr), "-p", "tcp", "--dport", str(port), "-j", "DROP"]
    raise ValueError(f"unsupported firewall: {firewall}")


def respond(incident: Incident, policy: ResponsePolicy, runner: Callable = subprocess.run) -> str:
    """Apply the response policy to one incident and record what happened in ``incident.action``."""
    if not severity_at_least(incident.severity, policy.block_min_severity):
        incident.action = (
            f"none: severity {incident.severity} is below the block threshold ({policy.block_min_severity})"
        )
    elif is_internal(incident.ip):
        incident.action = "skipped: internal address, never auto-blocked"
    elif is_allowlisted(incident.ip, policy.allowlist):
        incident.action = "skipped: address is on the allowlist"
    else:
        command = build_block_command(incident.ip, policy.firewall, policy.port)
        text = " ".join(command)
        if not policy.enforce:
            incident.action = f"dry-run: would run: {text}"
        elif shutil.which(command[0]) is None:
            incident.action = f"failed: {command[0]} not found on this system"
        else:
            try:
                result = runner(command, capture_output=True, text=True, timeout=15)
            except (OSError, subprocess.SubprocessError) as exc:
                incident.action = f"failed: {exc.__class__.__name__}"
            else:
                if result.returncode == 0:
                    incident.action = f"blocked: ran: {text}"
                else:
                    detail = (result.stderr or "").strip()[:200] or f"exit code {result.returncode}"
                    incident.action = f"failed: {detail} (are you running as root?)"
    return incident.action
