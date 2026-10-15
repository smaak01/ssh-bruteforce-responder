from sshresponder.detector import BruteForceDetector


def detector():
    return BruteForceDetector(threshold=5, window_seconds=120, correlation_seconds=600)


def test_no_incident_below_threshold(make_event):
    events = [make_event(i) for i in range(4)]
    assert detector().run(events) == []


def test_incident_raised_at_threshold(make_event):
    events = [make_event(i * 10) for i in range(5)]  # 5 failures in 40 seconds
    incidents = detector().run(events)
    assert len(incidents) == 1
    assert incidents[0].ip == "203.0.113.45"
    assert incidents[0].attempts == 5


def test_slow_attempts_outside_window_do_not_trigger(make_event):
    events = [make_event(i * 60) for i in range(10)]  # one a minute, never 5 inside 120s
    assert detector().run(events) == []


def test_continuing_burst_is_one_incident(make_event):
    events = [make_event(i) for i in range(20)]
    incidents = detector().run(events)
    assert len(incidents) == 1
    assert incidents[0].attempts == 20


def test_separate_bursts_make_separate_incidents(make_event):
    first = [make_event(i) for i in range(5)]
    second = [make_event(1000 + i) for i in range(5)]
    incidents = detector().run(first + second)
    assert [i.attempts for i in incidents] == [5, 5]


def test_each_ip_is_counted_separately(make_event):
    events = []
    for i in range(3):
        events.append(make_event(i, ip="203.0.113.1"))
        events.append(make_event(i, ip="203.0.113.2"))
    assert detector().run(events) == []  # 3 + 3 must not add up to 6


def test_collects_usernames_and_invalid_user_count(make_event):
    events = [
        make_event(0, user="root"),
        make_event(1, user="admin", invalid=True),
        make_event(2, user="test", invalid=True),
        make_event(3, user="oracle", invalid=True),
        make_event(4, user="root"),
    ]
    incident = detector().run(events)[0]
    assert incident.usernames == {"root", "admin", "test", "oracle"}
    assert incident.invalid_user_attempts == 3


def test_success_shortly_after_attack_marks_compromise(make_event):
    events = [make_event(i) for i in range(6)]
    events.append(make_event(300, outcome="accepted", user="ubuntu"))
    incident = detector().run(events)[0]
    assert incident.compromised_user == "ubuntu"


def test_success_long_after_attack_is_not_flagged(make_event):
    events = [make_event(i) for i in range(6)]
    events.append(make_event(2000, outcome="accepted", user="ubuntu"))
    assert detector().run(events)[0].compromised_user is None


def test_success_from_a_different_ip_is_not_flagged(make_event):
    events = [make_event(i) for i in range(6)]
    events.append(make_event(60, ip="203.0.113.99", outcome="accepted", user="alice"))
    assert detector().run(events)[0].compromised_user is None


def test_legitimate_typos_then_login_raise_nothing(make_event):
    events = [
        make_event(0, ip="192.168.1.20", user="alice"),
        make_event(6, ip="192.168.1.20", user="alice"),
        make_event(14, ip="192.168.1.20", outcome="accepted", user="alice"),
    ]
    assert detector().run(events) == []


def test_unsorted_input_is_handled(make_event):
    events = [make_event(i) for i in range(5)]
    assert len(detector().run(list(reversed(events)))) == 1
