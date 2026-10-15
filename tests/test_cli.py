import json
from pathlib import Path

from sshresponder.cli import main

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "auth.log"


def run(monkeypatch, capsys, *extra):
    # Empty values stop a developer's real .env from triggering API calls or Discord posts.
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", "")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    code = main(["--log", str(SAMPLE), "--year", "2026", *extra])
    return code, capsys.readouterr().out


def test_sample_log_end_to_end(monkeypatch, capsys, tmp_path):
    out_file = tmp_path / "incidents.jsonl"
    code, output = run(monkeypatch, capsys, "--output", str(out_file))

    assert code == 0
    assert "DRY-RUN" in output
    assert "4 incident(s)" in output

    records = [json.loads(line) for line in out_file.read_text().splitlines()]
    severity_by_ip = {r["ip"]: r["severity"] for r in records}
    assert severity_by_ip == {
        "203.0.113.45": "critical",
        "192.168.1.50": "high",
        "198.51.100.23": "medium",
        "198.51.100.77": "low",
    }

    actions = {r["ip"]: r["action"] for r in records}
    assert actions["203.0.113.45"].startswith("dry-run: would run: ufw deny from 203.0.113.45")
    assert actions["192.168.1.50"].startswith("skipped: internal")
    assert actions["198.51.100.23"].startswith("none:")
    assert records[0]["compromised_user"] == "ubuntu"  # sorted by risk, critical first


def test_the_legitimate_user_is_not_flagged(monkeypatch, capsys):
    _, output = run(monkeypatch, capsys)
    assert "192.168.1.20" not in output


def test_missing_log_file_is_a_clean_error(capsys):
    assert main(["--log", "does-not-exist.log"]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_bad_allowlist_is_a_clean_error(capsys):
    assert main(["--log", str(SAMPLE), "--allowlist", "not-an-ip"]) == 2
    assert "invalid --allowlist" in capsys.readouterr().err
