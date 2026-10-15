from datetime import datetime

from sshresponder.parser import parse_line, parse_lines

FAILED = "Oct 15 02:14:03 web01 sshd[2211]: Failed password for root from 203.0.113.45 port 51234 ssh2"
INVALID = "Oct 15 02:14:04 web01 sshd[2212]: Failed password for invalid user admin from 203.0.113.45 port 51235 ssh2"
ACCEPTED = "Oct  5 02:16:41 web01 sshd[2300]: Accepted password for ubuntu from 203.0.113.45 port 51400 ssh2"


def test_parses_failed_password():
    event = parse_line(FAILED, year=2026)
    assert event is not None
    assert (event.outcome, event.user, event.ip, event.port) == ("failed", "root", "203.0.113.45", 51234)
    assert event.host == "web01"
    assert event.invalid_user is False
    assert event.timestamp == datetime(2026, 10, 15, 2, 14, 3)


def test_flags_invalid_user():
    event = parse_line(INVALID, year=2026)
    assert event.user == "admin"
    assert event.invalid_user is True


def test_parses_accepted_login_with_padded_day():
    event = parse_line(ACCEPTED, year=2026)
    assert event.outcome == "accepted"
    assert event.user == "ubuntu"
    assert event.timestamp == datetime(2026, 10, 5, 2, 16, 41)


def test_parses_iso_timestamps():
    line = "2026-10-15T02:14:03.123456+04:00 web01 sshd[1]: Failed password for root from 203.0.113.45 port 22 ssh2"
    event = parse_line(line, year=1999)  # year is ignored for ISO timestamps
    assert event.timestamp == datetime(2026, 10, 15, 2, 14, 3, 123456)


def test_parses_ipv6_source():
    line = "Oct 15 02:14:03 web01 sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2"
    assert parse_line(line, year=2026).ip == "2001:db8::1"


def test_ignores_unrelated_and_noise_lines():
    noise = [
        "Oct 15 02:14:05 web01 sshd[2211]: Invalid user admin from 203.0.113.45 port 51235",
        "Oct 15 02:14:05 web01 CRON[1]: pam_unix(cron:session): session opened for user root",
        "Oct 15 02:14:05 web01 sshd[2211]: Failed none for invalid user x from 203.0.113.45 port 22 ssh2",
        "Oct 15 02:14:05 web01 sshd[2211]: Failed password for root from 999.1.1.1 port 22 ssh2",
        "Feb 30 02:14:05 web01 sshd[2211]: Failed password for root from 203.0.113.45 port 22 ssh2",
        "complete garbage",
        "",
    ]
    for line in noise:
        assert parse_line(line, year=2026) is None, line


def test_parse_lines_yields_only_events():
    events = list(parse_lines([FAILED, "noise", INVALID, ACCEPTED], year=2026))
    assert [e.outcome for e in events] == ["failed", "failed", "accepted"]
