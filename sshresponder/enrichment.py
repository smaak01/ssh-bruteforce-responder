"""Threat-intelligence enrichment using the AbuseIPDB API (free tier)."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, Optional

import requests

from .models import Enrichment, Incident
from .util import is_internal

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBClient:
    """Look up an IP's abuse confidence score, with an on-disk cache.

    The free tier allows about 1000 checks a day, so results are cached for
    ``cache_ttl_hours``. Every failure is turned into an Enrichment with an
    explanatory note instead of an exception: a broken lookup must never stop
    the pipeline from alerting.
    """

    def __init__(
        self,
        api_key: str,
        cache_path: Optional[Path] = None,
        cache_ttl_hours: int = 24,
        timeout: int = 10,
        session=None,
    ) -> None:
        self.api_key = api_key
        self.cache_path = Path(cache_path) if cache_path else None
        self.ttl = timedelta(hours=cache_ttl_hours)
        self.timeout = timeout
        self.session = session or requests.Session()
        self._cache: Dict[str, dict] = self._load_cache()

    def lookup(self, ip: str) -> Enrichment:
        cached = self._from_cache(ip)
        if cached is not None:
            return cached

        try:
            response = self.session.get(
                ABUSEIPDB_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            # Only the exception class is reported, never its text, so the key can't leak.
            return Enrichment(source="abuseipdb", note=f"lookup failed ({exc.__class__.__name__})")

        if response.status_code == 429:
            return Enrichment(source="abuseipdb", note="rate limit reached (free tier: 1000 checks/day)")
        if response.status_code in (401, 403):
            return Enrichment(source="abuseipdb", note="API key rejected")
        if response.status_code != 200:
            return Enrichment(source="abuseipdb", note=f"unexpected HTTP {response.status_code}")

        try:
            data = response.json()["data"]
            result = Enrichment(
                source="abuseipdb",
                abuse_score=int(data.get("abuseConfidenceScore", 0)),
                country=data.get("countryCode"),
                total_reports=data.get("totalReports"),
                isp=data.get("isp"),
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            return Enrichment(source="abuseipdb", note="unreadable response")

        self._store(ip, result)
        return result

    # --- cache -----------------------------------------------------------------

    def _load_cache(self) -> Dict[str, dict]:
        if self.cache_path is None or not self.cache_path.is_file():
            return {}
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _from_cache(self, ip: str) -> Optional[Enrichment]:
        entry = self._cache.get(ip)
        if not entry:
            return None
        try:
            fetched_at = datetime.fromisoformat(entry["fetched_at"])
            if datetime.now() - fetched_at > self.ttl:
                return None
            return Enrichment(**entry["data"])
        except (KeyError, TypeError, ValueError):
            return None

    def _store(self, ip: str, result: Enrichment) -> None:
        self._cache[ip] = {"fetched_at": datetime.now().isoformat(), "data": asdict(result)}
        if self.cache_path is None:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache, indent=2), encoding="utf-8")
        except OSError:
            pass  # a cache that can't be written is not worth failing over


def enrich_incidents(
    incidents: Iterable[Incident],
    client: Optional[AbuseIPDBClient],
    disabled_reason: str = "enrichment disabled",
) -> None:
    """Attach reputation data to each incident (internal addresses are never sent out)."""
    for incident in incidents:
        if client is None:
            incident.enrichment = Enrichment(note=disabled_reason)
        elif is_internal(incident.ip):
            incident.enrichment = Enrichment(source="local", note="internal address, lookup skipped")
        else:
            incident.enrichment = client.lookup(incident.ip)
