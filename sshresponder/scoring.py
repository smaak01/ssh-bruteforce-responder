"""Risk scoring: turn an incident into a 0-100 score, a severity and a plain-English explanation."""

from __future__ import annotations

from typing import List, Tuple

from .models import Incident

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
PRIVILEGED_USERS = {"root", "admin", "administrator"}


def severity_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[minimum]


def mitre_for(incident: Incident) -> List[str]:
    techniques = ["T1110 Brute Force"]
    if incident.compromised_user:
        techniques.append("T1078 Valid Accounts")
    return techniques


def calculate_risk(incident: Incident) -> Tuple[int, List[str]]:
    """Return (score, reasons). Every point added is explained, so analysts can audit the score."""
    score = 0
    reasons: List[str] = []

    # How much noise did the attacker make?
    if incident.attempts >= 100:
        points = 40
    elif incident.attempts >= 30:
        points = 30
    elif incident.attempts >= 10:
        points = 20
    else:
        points = 10
    score += points
    reasons.append(f"{incident.attempts} failed logins (+{points})")

    # What did they try?
    if incident.attempts and incident.invalid_user_attempts / incident.attempts >= 0.5:
        score += 10
        reasons.append("mostly non-existent usernames, typical of automated guessing (+10)")
    if len(incident.usernames) >= 5:
        score += 10
        reasons.append(f"{len(incident.usernames)} different usernames tried (+10)")
    if {name.lower() for name in incident.usernames} & PRIVILEGED_USERS:
        score += 5
        reasons.append("privileged account targeted (+5)")

    # Is the source already known to be bad?
    abuse = incident.enrichment.abuse_score
    if abuse is not None:
        points = round(abuse * 0.3)
        if points:
            score += points
            reasons.append(f"AbuseIPDB abuse confidence {abuse}% (+{points})")

    # Did the attack work?
    if incident.compromised_user:
        score += 40
        reasons.append("successful login from the same IP after the attack (+40)")

    return min(score, 100), reasons


def score_incident(incident: Incident) -> Incident:
    """Fill in risk_score, severity, reasons and MITRE techniques on the incident."""
    incident.risk_score, incident.reasons = calculate_risk(incident)
    incident.severity = severity_for(incident.risk_score)
    incident.mitre = mitre_for(incident)
    return incident
