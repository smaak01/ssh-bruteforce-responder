"""Command-line entry point: parse -> detect -> enrich -> score -> respond -> alert."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from . import __version__
from .detector import BruteForceDetector
from .enrichment import AbuseIPDBClient, enrich_incidents
from .notifier import format_console_alert, send_discord_alert
from .parser import parse_file
from .responder import SUPPORTED_FIREWALLS, ResponsePolicy, respond
from .scoring import SEVERITY_ORDER, score_incident, severity_at_least
from .util import parse_allowlist

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is optional; plain environment variables still work
    load_dotenv = None

LEVELS = tuple(SEVERITY_ORDER)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sshresponder",
        description="Detect SSH brute-force attacks in an auth log, enrich and score them, "
        "alert via Discord and (optionally) block the source IP.",
    )
    parser.add_argument("--log", required=True, type=Path, help="path to an sshd auth log, e.g. /var/log/auth.log")
    parser.add_argument("--threshold", type=int, default=5, help="failed logins within the window that raise an incident (default: 5)")
    parser.add_argument("--window", type=int, default=120, help="sliding window in seconds (default: 120)")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="year for classic syslog timestamps, which omit it (default: current year)")
    parser.add_argument("--no-enrich", action="store_true", help="skip AbuseIPDB lookups")
    parser.add_argument("--cache", type=Path, default=Path(".cache/abuseipdb.json"), help="AbuseIPDB cache file")
    parser.add_argument("--alert-min", choices=LEVELS, default="medium", help="lowest severity sent to Discord (default: medium)")
    parser.add_argument("--block-min", choices=LEVELS, default="high", help="lowest severity that triggers a block (default: high)")
    parser.add_argument("--firewall", choices=SUPPORTED_FIREWALLS, default="ufw", help="firewall used for blocks (default: ufw)")
    parser.add_argument("--port", type=int, default=22, help="SSH port to block (default: 22)")
    parser.add_argument("--allowlist", default="", help="comma-separated IPs/CIDRs that must never be blocked")
    parser.add_argument("--enforce", action="store_true", help="actually run the block command (default: dry-run, nothing is changed)")
    parser.add_argument("--output", type=Path, help="write the incidents to this file as JSON Lines (audit log)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _count(incidents, prefix: str) -> int:
    return sum(1 for incident in incidents if incident.action.startswith(prefix))


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if load_dotenv is not None:
        load_dotenv()

    if args.threshold < 1 or args.window < 1:
        print("error: --threshold and --window must be positive", file=sys.stderr)
        return 2
    if not 1 <= args.port <= 65535:
        print("error: --port must be between 1 and 65535", file=sys.stderr)
        return 2
    try:
        allowlist = parse_allowlist(args.allowlist.split(","))
    except ValueError as exc:
        print(f"error: invalid --allowlist ({exc})", file=sys.stderr)
        return 2

    try:
        events = list(parse_file(args.log, year=args.year))
    except OSError as exc:
        print(f"error: cannot read {args.log}: {exc.strerror or exc}", file=sys.stderr)
        return 1

    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    webhook = os.getenv("DISCORD_WEBHOOK_URL", "").strip()

    client = None
    if args.no_enrich:
        enrich_status = "disabled (--no-enrich)"
    elif not api_key:
        enrich_status = "disabled (set ABUSEIPDB_API_KEY in .env to enable)"
    else:
        client = AbuseIPDBClient(api_key, cache_path=args.cache)
        enrich_status = "AbuseIPDB (24h cache)"

    mode = "ENFORCE (firewall rules will be applied)" if args.enforce else "DRY-RUN (no changes will be made)"
    print(f"sshresponder {__version__} | mode: {mode}")
    print(f"Enrichment: {enrich_status}")
    print(f"Discord alerts: {'enabled' if webhook else 'disabled (set DISCORD_WEBHOOK_URL in .env to enable)'}")
    failed = sum(1 for e in events if e.outcome == "failed")
    print(f"Parsed {len(events)} sshd auth events ({failed} failed, {len(events) - failed} accepted) from {args.log}")
    print()

    incidents = BruteForceDetector(args.threshold, args.window).run(events)
    enrich_incidents(incidents, client, disabled_reason=f"enrichment {enrich_status.split(' (')[0]}")

    policy = ResponsePolicy(
        block_min_severity=args.block_min,
        firewall=args.firewall,
        port=args.port,
        enforce=args.enforce,
        allowlist=allowlist,
    )
    for incident in incidents:
        score_incident(incident)
        respond(incident, policy)
    incidents.sort(key=lambda item: item.risk_score, reverse=True)

    alerts_sent = 0
    for incident in incidents:
        print(format_console_alert(incident))
        if webhook and severity_at_least(incident.severity, args.alert_min):
            if send_discord_alert(incident, webhook):
                alerts_sent += 1

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as handle:
            for incident in incidents:
                handle.write(json.dumps(incident.to_dict()) + "\n")

    by_level = ", ".join(
        f"{sum(1 for i in incidents if i.severity == level)} {level}" for level in reversed(LEVELS)
    )
    print(
        f"Summary: {len(incidents)} incident(s) [{by_level}] | Discord alerts sent: {alerts_sent} | "
        f"blocks: {_count(incidents, 'blocked')} applied, {_count(incidents, 'dry-run')} dry-run, "
        f"{_count(incidents, 'failed')} failed"
    )
    return 0
