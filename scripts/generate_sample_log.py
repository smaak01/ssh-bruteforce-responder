#!/usr/bin/env python3
"""Generate a realistic, deterministic sample auth.log for demos and tests.

All attacker addresses come from the RFC 5737 documentation ranges
(203.0.113.0/24 and 198.51.100.0/24), so no real host is ever involved.

Usage:  python scripts/generate_sample_log.py
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

HOST = "web01"
DAY = datetime(2026, 10, 15)
random.seed(7)

lines = []  # (timestamp, text)


def stamp(ts):
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"  # classic syslog: "Oct 15 02:14:03"


def at(hour, minute, second=0):
    return DAY.replace(hour=hour, minute=minute, second=second)


def add(ts, pid, message, program="sshd"):
    lines.append((ts, f"{stamp(ts)} {HOST} {program}[{pid}]: {message}"))


def brute_force(ip, start, attempts, users, existing, duration):
    """Emit the log lines a password-guessing bot leaves behind."""
    step = duration / max(attempts - 1, 1)
    last = start
    for i in range(attempts):
        ts = start + timedelta(seconds=round(i * step))
        user = users[i % len(users)]
        pid = random.randint(10000, 60000)
        port = random.randint(1024, 65535)
        if user in existing:
            add(ts, pid, f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}")
            add(ts, pid, f"Failed password for {user} from {ip} port {port} ssh2")
        else:
            add(ts, pid, f"Invalid user {user} from {ip} port {port}")
            add(ts, pid, f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        add(ts, pid, f"Connection closed by authenticating user {user} {ip} port {port} [preauth]")
        last = ts
    return last


# --- Normal background activity ---------------------------------------------
add(at(8, 2, 11), 1201, "Accepted publickey for deploy from 10.0.0.12 port 51122 ssh2: RSA SHA256:Zk3dQ0b2xX7mV1pYw9aTn5uLq8cHs4eRjGfIoBvN6yA")
add(at(8, 2, 11), 1201, "pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)")
add(at(3, 0, 1), 900, "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", program="CRON")
add(at(12, 0, 1), 901, "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", program="CRON")

# A legitimate user mistypes a password twice, then gets in. Must NOT raise an incident.
add(at(11, 20, 5), 4101, "Failed password for alice from 192.168.1.20 port 40211 ssh2")
add(at(11, 20, 11), 4101, "Failed password for alice from 192.168.1.20 port 40211 ssh2")
add(at(11, 20, 19), 4101, "Accepted password for alice from 192.168.1.20 port 40211 ssh2")

# --- Attack 1: external bot, ~40 guesses, then a lucky login (critical) -------
attack_end = brute_force(
    ip="203.0.113.45",
    start=at(2, 14, 3),
    attempts=41,
    users=["root", "admin", "ubuntu", "test", "oracle", "postgres", "ftpuser", "user", "guest"],
    existing={"root", "ubuntu"},
    duration=88,
)
add(attack_end + timedelta(seconds=37), 31337, "Accepted password for ubuntu from 203.0.113.45 port 52411 ssh2")

# --- Attack 2: slower external scan, never gets in (medium) -------------------
brute_force(
    ip="198.51.100.23",
    start=at(9, 31, 10),
    attempts=15,
    users=["root", "admin", "test", "oracle", "git", "pi"],
    existing={"root"},
    duration=70,
)

# --- Attack 3: noisy internal host (high, but must never be auto-blocked) -----
brute_force(
    ip="192.168.1.50",
    start=at(14, 2, 0),
    attempts=35,
    users=["root", "admin", "deploy", "jenkins", "git", "backup", "svc", "test"],
    existing={"root", "deploy"},
    duration=60,
)

# --- Attack 4: a few guesses against one account (low) ------------------------
brute_force(
    ip="198.51.100.77",
    start=at(17, 45, 0),
    attempts=6,
    users=["deploy"],
    existing={"deploy"},
    duration=25,
)

lines.sort(key=lambda item: item[0])  # stable: keeps same-second lines in order

out = Path(__file__).resolve().parent.parent / "samples" / "auth.log"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("\n".join(text for _, text in lines) + "\n", encoding="utf-8")
print(f"wrote {len(lines)} lines to {out}")
