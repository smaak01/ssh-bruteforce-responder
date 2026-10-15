"""Alerting: console output and Discord webhook notifications."""

from __future__ import annotations

import sys
from datetime import datetime, timezone

import requests

from .models import Enrichment, Incident
from .util import sanitize

SEVERITY_COLORS = {
    "low": 0x2ECC71,
    "medium": 0xF1C40F,
    "high": 0xE67E22,
    "critical": 0xE74C3C,
}

# Only post to real Discord webhooks, even if the configured URL is wrong or tampered with.
ALLOWED_WEBHOOK_PREFIXES = (
    "https://discord.com/api/webhooks/",
    "https://discordapp.com/api/webhooks/",
)


def describe_reputation(enrichment: Enrichment) -> str:
    if enrichment.abuse_score is None:
        return enrichment.note or "unavailable"
    parts = [f"AbuseIPDB abuse confidence {enrichment.abuse_score}%"]
    if enrichment.total_reports is not None:
        parts.append(f"{enrichment.total_reports} reports")
    if enrichment.country:
        parts.append(sanitize(enrichment.country, 8))
    if enrichment.isp:
        parts.append(sanitize(enrichment.isp, 40))
    return ", ".join(parts)


def _usernames_preview(incident: Incident, limit: int = 8) -> str:
    names = sorted(incident.usernames)
    shown = ", ".join(sanitize(name) for name in names[:limit])
    extra = len(names) - limit
    return shown + (f" (+{extra} more)" if extra > 0 else "")


def format_console_alert(incident: Incident) -> str:
    lines = [
        f"[{incident.severity.upper()}] {incident.ip}  risk {incident.risk_score}/100",
        f"  attempts   : {incident.attempts} failed logins in {int(incident.duration_seconds)}s "
        f"(starting {incident.first_seen:%Y-%m-%d %H:%M:%S})",
        f"  usernames  : {_usernames_preview(incident)} ({len(incident.usernames)} distinct)",
        f"  reputation : {describe_reputation(incident.enrichment)}",
    ]
    if incident.compromised_user:
        lines.append(
            f"  !! COMPROMISE: successful login as '{sanitize(incident.compromised_user)}' "
            "from this IP after the attack"
        )
    lines += [
        f"  MITRE      : {', '.join(incident.mitre)}",
        f"  why        : {'; '.join(incident.reasons)}",
        f"  action     : {incident.action}",
        "",
    ]
    return "\n".join(lines)


def build_discord_payload(incident: Incident) -> dict:
    fields = [
        {"name": "Source IP", "value": f"`{incident.ip}`", "inline": True},
        {"name": "Risk score", "value": f"{incident.risk_score}/100", "inline": True},
        {
            "name": "Failed logins",
            "value": f"{incident.attempts} in {int(incident.duration_seconds)}s",
            "inline": True,
        },
        {"name": "Usernames tried", "value": f"`{_usernames_preview(incident)}`"},
        {"name": "Reputation", "value": describe_reputation(incident.enrichment)},
        {"name": "MITRE ATT&CK", "value": ", ".join(incident.mitre)},
        {"name": "Why this score", "value": "\n".join(f"• {r}" for r in incident.reasons)[:1000]},
        {"name": "Response", "value": incident.action[:1000]},
    ]
    if incident.compromised_user:
        fields.insert(
            0,
            {
                "name": "⚠ POSSIBLE COMPROMISE",
                "value": f"A login succeeded as `{sanitize(incident.compromised_user)}` "
                "from this IP after the attack. Investigate immediately.",
            },
        )
    return {
        # Stop attacker-controlled text (e.g. a username of "@everyone") from pinging anyone.
        "allowed_mentions": {"parse": []},
        "embeds": [
            {
                "title": f"[{incident.severity.upper()}] SSH brute force from {incident.ip}",
                "color": SEVERITY_COLORS[incident.severity],
                "fields": fields,
                "footer": {"text": "ssh-bruteforce-responder"},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }


def send_discord_alert(incident: Incident, webhook_url: str, timeout: int = 10, session=None) -> bool:
    """Post an alert to Discord. Returns True on success; never raises."""
    if not webhook_url.startswith(ALLOWED_WEBHOOK_PREFIXES):
        print("warning: DISCORD_WEBHOOK_URL is not a Discord webhook URL; alert not sent", file=sys.stderr)
        return False

    post = (session or requests).post
    try:
        response = post(webhook_url, json=build_discord_payload(incident), timeout=timeout)
    except requests.RequestException as exc:
        print(f"warning: could not reach Discord ({exc.__class__.__name__})", file=sys.stderr)
        return False

    if response.status_code in (200, 204):
        return True
    print(f"warning: Discord returned HTTP {response.status_code}; alert not delivered", file=sys.stderr)
    return False
