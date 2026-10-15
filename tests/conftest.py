from datetime import datetime, timedelta

import pytest

from sshresponder.models import AuthEvent, Incident

BASE = datetime(2026, 10, 15, 12, 0, 0)


@pytest.fixture
def make_event():
    """Factory for AuthEvents, positioned ``seconds`` after a fixed base time."""

    def _make(seconds=0, ip="203.0.113.45", outcome="failed", user="root", invalid=False):
        return AuthEvent(
            timestamp=BASE + timedelta(seconds=seconds),
            host="web01",
            outcome=outcome,
            method="password",
            user=user,
            ip=ip,
            port=40000,
            invalid_user=invalid,
        )

    return _make


@pytest.fixture
def make_incident():
    """Factory for Incidents with sensible, low-risk defaults."""

    def _make(**overrides):
        values = dict(
            ip="203.0.113.45",
            first_seen=BASE,
            last_seen=BASE + timedelta(seconds=60),
            attempts=10,
            usernames={"bob"},
            invalid_user_attempts=0,
        )
        values.update(overrides)
        return Incident(**values)

    return _make
