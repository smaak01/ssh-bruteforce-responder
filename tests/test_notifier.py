import json
from types import SimpleNamespace

import requests

from sshresponder.notifier import build_discord_payload, format_console_alert, send_discord_alert

WEBHOOK = "https://discord.com/api/webhooks/123456/abcdef"


class FakeSession:
    def __init__(self, status_code=204, error=None):
        self.status_code = status_code
        self.error = error
        self.calls = []

    def post(self, url, json=None, timeout=None):
        self.calls.append((url, json))
        if self.error:
            raise self.error
        return SimpleNamespace(status_code=self.status_code)


def test_payload_cannot_ping_anyone_and_neutralises_usernames(make_incident):
    incident = make_incident(severity="high", usernames={"@everyone", "bad`name"})
    payload = build_discord_payload(incident)
    assert payload["allowed_mentions"] == {"parse": []}
    text = json.dumps(payload)
    assert "bad`name" not in text
    assert "bad?name" in text


def test_payload_highlights_a_compromise(make_incident):
    incident = make_incident(severity="critical", compromised_user="ubuntu")
    fields = build_discord_payload(incident)["embeds"][0]["fields"]
    assert fields[0]["name"].endswith("POSSIBLE COMPROMISE")


def test_console_output_strips_terminal_escape_codes(make_incident):
    incident = make_incident(usernames={"evil\x1b[31mred", "line\nbreak"})
    output = format_console_alert(incident)
    assert "\x1b" not in output
    assert "line\nbreak" not in output


def test_sends_to_a_discord_webhook(make_incident):
    session = FakeSession()
    assert send_discord_alert(make_incident(severity="high"), WEBHOOK, session=session) is True
    url, body = session.calls[0]
    assert url == WEBHOOK
    assert body["embeds"][0]["title"].startswith("[HIGH]")


def test_refuses_to_post_to_non_discord_urls(make_incident):
    session = FakeSession()
    assert send_discord_alert(make_incident(), "https://evil.example.com/hook", session=session) is False
    assert session.calls == []


def test_network_errors_do_not_raise(make_incident):
    session = FakeSession(error=requests.ConnectionError("boom"))
    assert send_discord_alert(make_incident(), WEBHOOK, session=session) is False


def test_http_errors_are_reported_as_failure(make_incident):
    assert send_discord_alert(make_incident(), WEBHOOK, session=FakeSession(status_code=429)) is False
