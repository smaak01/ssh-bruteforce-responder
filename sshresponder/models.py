"""Plain data containers shared by every stage of the pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import List, Optional, Set


@dataclass(frozen=True)
class AuthEvent:
    """One parsed sshd authentication event (a failed or accepted login)."""

    timestamp: datetime
    host: str
    outcome: str  # "failed" or "accepted"
    method: str  # "password", "publickey", ...
    user: str
    ip: str
    port: int
    invalid_user: bool = False  # the username does not exist on the host


@dataclass
class Enrichment:
    """Threat-intelligence data about a source IP."""

    source: str = "none"
    abuse_score: Optional[int] = None  # 0-100 abuse confidence (AbuseIPDB)
    country: Optional[str] = None
    total_reports: Optional[int] = None
    isp: Optional[str] = None
    note: str = ""  # why data is missing (rate limit, disabled, ...)


@dataclass
class Incident:
    """A detected brute-force attempt from a single source IP."""

    ip: str
    first_seen: datetime
    last_seen: datetime
    attempts: int = 0
    usernames: Set[str] = field(default_factory=set)
    invalid_user_attempts: int = 0
    hosts: Set[str] = field(default_factory=set)
    compromised_user: Optional[str] = None  # set if a login succeeded after the attack
    enrichment: Enrichment = field(default_factory=Enrichment)
    risk_score: int = 0
    severity: str = "low"
    reasons: List[str] = field(default_factory=list)
    mitre: List[str] = field(default_factory=list)
    action: str = "none"

    @property
    def duration_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()

    def to_dict(self) -> dict:
        """JSON-serialisable view, used for the audit log."""
        return {
            "ip": self.ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": self.duration_seconds,
            "attempts": self.attempts,
            "usernames": sorted(self.usernames),
            "invalid_user_attempts": self.invalid_user_attempts,
            "hosts": sorted(self.hosts),
            "compromised_user": self.compromised_user,
            "enrichment": asdict(self.enrichment),
            "risk_score": self.risk_score,
            "severity": self.severity,
            "reasons": self.reasons,
            "mitre": self.mitre,
            "action": self.action,
        }
