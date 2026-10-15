import requests

from sshresponder.enrichment import AbuseIPDBClient, enrich_incidents

GOOD = {
    "data": {
        "abuseConfidenceScore": 97,
        "countryCode": "CN",
        "totalReports": 1203,
        "isp": "Example ISP",
    }
}


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse(200, GOOD)
        self.error = error
        self.calls = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "params": params})
        if self.error:
            raise self.error
        return self.response


def test_parses_a_successful_lookup():
    result = AbuseIPDBClient("secret", session=FakeSession()).lookup("203.0.113.45")
    assert (result.abuse_score, result.country, result.total_reports, result.isp) == (
        97, "CN", 1203, "Example ISP",
    )


def test_sends_key_header_and_ip_param():
    session = FakeSession()
    AbuseIPDBClient("secret", session=session).lookup("203.0.113.45")
    call = session.calls[0]
    assert call["headers"]["Key"] == "secret"
    assert call["params"]["ipAddress"] == "203.0.113.45"


def test_results_are_cached_on_disk(tmp_path):
    cache = tmp_path / "cache.json"
    first = FakeSession()
    AbuseIPDBClient("secret", cache_path=cache, session=first).lookup("203.0.113.45")
    assert len(first.calls) == 1

    second = FakeSession()
    result = AbuseIPDBClient("secret", cache_path=cache, session=second).lookup("203.0.113.45")
    assert second.calls == []  # served from the cache file
    assert result.abuse_score == 97


def test_rate_limit_degrades_gracefully():
    session = FakeSession(FakeResponse(429))
    result = AbuseIPDBClient("secret", session=session).lookup("203.0.113.45")
    assert result.abuse_score is None
    assert "rate limit" in result.note


def test_rejected_key_is_reported_without_leaking_it():
    result = AbuseIPDBClient("secret", session=FakeSession(FakeResponse(401))).lookup("203.0.113.45")
    assert result.note == "API key rejected"
    assert "secret" not in result.note


def test_network_failure_degrades_gracefully():
    session = FakeSession(error=requests.ConnectionError("secret in message"))
    result = AbuseIPDBClient("secret", session=session).lookup("203.0.113.45")
    assert result.abuse_score is None
    assert "ConnectionError" in result.note
    assert "secret" not in result.note


def test_failed_lookups_are_not_cached(tmp_path):
    session = FakeSession(FakeResponse(429))
    client = AbuseIPDBClient("secret", cache_path=tmp_path / "c.json", session=session)
    client.lookup("203.0.113.45")
    client.lookup("203.0.113.45")
    assert len(session.calls) == 2


def test_garbage_response_is_handled():
    session = FakeSession(FakeResponse(200, {"unexpected": True}))
    assert AbuseIPDBClient("secret", session=session).lookup("203.0.113.45").note == "unreadable response"


def test_enrich_incidents_without_a_client(make_incident):
    incident = make_incident()
    enrich_incidents([incident], None, disabled_reason="enrichment disabled")
    assert incident.enrichment.note == "enrichment disabled"


def test_internal_addresses_are_never_sent_to_the_api(make_incident):
    session = FakeSession()
    incident = make_incident(ip="192.168.1.50")
    enrich_incidents([incident], AbuseIPDBClient("secret", session=session))
    assert session.calls == []
    assert incident.enrichment.source == "local"
