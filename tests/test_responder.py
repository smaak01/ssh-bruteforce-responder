from types import SimpleNamespace

import pytest

from sshresponder import responder
from sshresponder.responder import ResponsePolicy, build_block_command, respond
from sshresponder.util import is_internal, parse_allowlist


def test_ufw_command():
    assert build_block_command("203.0.113.45", "ufw", 22) == [
        "ufw", "deny", "from", "203.0.113.45", "to", "any", "port", "22", "proto", "tcp",
    ]


def test_iptables_command():
    assert build_block_command("203.0.113.45", "iptables", 2222) == [
        "iptables", "-I", "INPUT", "-s", "203.0.113.45", "-p", "tcp", "--dport", "2222", "-j", "DROP",
    ]


def test_ipv6_uses_ip6tables():
    assert build_block_command("2001:db8::1", "iptables")[0] == "ip6tables"


@pytest.mark.parametrize(
    "bad", ["1.2.3.4; rm -rf /", "$(reboot)", "not-an-ip", "1.2.3.4 -j ACCEPT", "1.2.3.4\n8.8.8.8", ""]
)
def test_command_injection_is_impossible(bad):
    with pytest.raises(ValueError):
        build_block_command(bad)


def test_rejects_bad_port_and_firewall():
    with pytest.raises(ValueError):
        build_block_command("203.0.113.45", port=70000)
    with pytest.raises(ValueError):
        build_block_command("203.0.113.45", firewall="pf")


def test_dry_run_never_executes(make_incident):
    calls = []
    incident = make_incident(severity="critical")
    respond(incident, ResponsePolicy(), runner=lambda *a, **k: calls.append(a))
    assert calls == []
    assert incident.action.startswith("dry-run: would run: ufw deny from 203.0.113.45")


def test_enforce_runs_the_command(make_incident, monkeypatch):
    monkeypatch.setattr(responder.shutil, "which", lambda name: f"/usr/sbin/{name}")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stderr="")

    incident = make_incident(severity="critical")
    respond(incident, ResponsePolicy(enforce=True), runner=fake_run)
    assert calls == [build_block_command("203.0.113.45")]
    assert incident.action.startswith("blocked:")


def test_enforce_reports_failures(make_incident, monkeypatch):
    monkeypatch.setattr(responder.shutil, "which", lambda name: f"/usr/sbin/{name}")
    runner = lambda command, **kwargs: SimpleNamespace(returncode=1, stderr="ERROR: you need to be root")
    incident = make_incident(severity="high")
    respond(incident, ResponsePolicy(enforce=True), runner=runner)
    assert incident.action.startswith("failed: ERROR: you need to be root")


def test_enforce_reports_missing_firewall_binary(make_incident, monkeypatch):
    monkeypatch.setattr(responder.shutil, "which", lambda name: None)
    incident = make_incident(severity="high")
    respond(incident, ResponsePolicy(enforce=True), runner=lambda *a, **k: pytest.fail("must not run"))
    assert incident.action == "failed: ufw not found on this system"


def test_internal_addresses_are_never_blocked(make_incident):
    incident = make_incident(ip="192.168.1.50", severity="critical")
    respond(incident, ResponsePolicy(enforce=True), runner=lambda *a, **k: pytest.fail("must not run"))
    assert incident.action.startswith("skipped: internal")


def test_allowlisted_addresses_are_never_blocked(make_incident):
    policy = ResponsePolicy(enforce=True, allowlist=parse_allowlist(["203.0.113.0/24"]))
    incident = make_incident(severity="critical")
    respond(incident, policy, runner=lambda *a, **k: pytest.fail("must not run"))
    assert incident.action.startswith("skipped: address is on the allowlist")


def test_below_threshold_takes_no_action(make_incident):
    incident = make_incident(severity="medium")
    respond(incident, ResponsePolicy(enforce=True), runner=lambda *a, **k: pytest.fail("must not run"))
    assert incident.action.startswith("none:")


@pytest.mark.parametrize(
    "ip, expected",
    [
        ("10.1.2.3", True), ("172.20.0.1", True), ("192.168.0.9", True), ("127.0.0.1", True),
        ("169.254.1.1", True), ("::1", True), ("fe80::1", True), ("::ffff:10.0.0.1", True),
        ("203.0.113.45", False), ("8.8.8.8", False), ("172.32.0.1", False),
    ],
)
def test_is_internal(ip, expected):
    assert is_internal(ip) is expected
