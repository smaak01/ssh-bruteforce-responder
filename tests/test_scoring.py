import pytest

from sshresponder.models import Enrichment
from sshresponder.scoring import score_incident, severity_at_least, severity_for

NINE_USERS = {"root", "admin", "ubuntu", "test", "oracle", "postgres", "ftpuser", "user", "guest"}


@pytest.mark.parametrize("attempts, expected", [(5, 10), (10, 20), (30, 30), (100, 40)])
def test_volume_tiers(make_incident, attempts, expected):
    incident = score_incident(make_incident(attempts=attempts))
    assert incident.risk_score == expected


def test_successful_login_after_attack_is_critical(make_incident):
    incident = score_incident(
        make_incident(attempts=41, usernames=NINE_USERS, invalid_user_attempts=30, compromised_user="ubuntu")
    )
    assert incident.risk_score == 95  # 30 + 10 + 10 + 5 + 40
    assert incident.severity == "critical"
    assert "T1078 Valid Accounts" in incident.mitre


def test_attack_without_compromise_only_maps_to_brute_force(make_incident):
    incident = score_incident(make_incident())
    assert incident.mitre == ["T1110 Brute Force"]


def test_bad_reputation_raises_the_score(make_incident):
    incident = make_incident(attempts=5, enrichment=Enrichment(source="abuseipdb", abuse_score=100))
    score_incident(incident)
    assert incident.risk_score == 40  # 10 for volume + 30 for reputation
    assert incident.severity == "medium"


def test_missing_reputation_adds_nothing(make_incident):
    incident = score_incident(make_incident(attempts=5, enrichment=Enrichment(note="disabled")))
    assert incident.risk_score == 10


def test_score_is_capped_at_100(make_incident):
    incident = score_incident(
        make_incident(
            attempts=100,
            usernames=NINE_USERS,
            invalid_user_attempts=90,
            compromised_user="root",
            enrichment=Enrichment(abuse_score=100),
        )
    )
    assert incident.risk_score == 100


def test_every_point_is_explained(make_incident):
    incident = score_incident(make_incident(attempts=41, usernames=NINE_USERS, invalid_user_attempts=30))
    assert len(incident.reasons) == 4


@pytest.mark.parametrize(
    "score, expected",
    [(0, "low"), (29, "low"), (30, "medium"), (54, "medium"), (55, "high"), (79, "high"), (80, "critical")],
)
def test_severity_boundaries(score, expected):
    assert severity_for(score) == expected


def test_severity_ordering():
    assert severity_at_least("critical", "high")
    assert severity_at_least("high", "high")
    assert not severity_at_least("medium", "high")
