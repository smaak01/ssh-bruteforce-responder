"""Sliding-window brute-force detection."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Deque, Dict, Iterable, List, Optional

from .models import AuthEvent, Incident


@dataclass
class _IpState:
    recent: Deque[AuthEvent] = field(default_factory=deque)  # failures inside the window
    last_failure: Optional[datetime] = None
    open_incident: Optional[Incident] = None  # burst still in progress
    last_incident: Optional[Incident] = None  # most recent one, for compromise correlation


class BruteForceDetector:
    """Raise an incident when one IP fails ``threshold`` logins within ``window_seconds``.

    Further failures from the same IP are folded into the same incident until it
    stays quiet for a full window. If a login *succeeds* from that IP within
    ``correlation_seconds`` of the attack, the incident is marked as a possible
    compromise (the attacker may have guessed a password).
    """

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 120,
        correlation_seconds: int = 600,
    ) -> None:
        if threshold < 1 or window_seconds < 1:
            raise ValueError("threshold and window_seconds must be positive")
        self.threshold = threshold
        self.window = window_seconds
        self.correlation = correlation_seconds

    def run(self, events: Iterable[AuthEvent]) -> List[Incident]:
        states: Dict[str, _IpState] = {}
        incidents: List[Incident] = []

        # Sort so the detector also works on logs that are slightly out of order.
        for event in sorted(events, key=lambda e: e.timestamp):
            state = states.setdefault(event.ip, _IpState())
            if event.outcome == "failed":
                self._on_failure(event, state, incidents)
            elif event.outcome == "accepted":
                self._on_success(event, state)
        return incidents

    def _on_failure(self, event: AuthEvent, state: _IpState, incidents: List[Incident]) -> None:
        # A long quiet gap ends the previous burst.
        if (
            state.last_failure is not None
            and (event.timestamp - state.last_failure).total_seconds() > self.window
        ):
            state.recent.clear()
            state.open_incident = None
        state.last_failure = event.timestamp

        state.recent.append(event)
        while (event.timestamp - state.recent[0].timestamp).total_seconds() > self.window:
            state.recent.popleft()

        if state.open_incident is not None:
            self._absorb(state.open_incident, event)
        elif len(state.recent) >= self.threshold:
            incident = Incident(
                ip=event.ip,
                first_seen=state.recent[0].timestamp,
                last_seen=event.timestamp,
            )
            for past in state.recent:
                self._absorb(incident, past)
            state.open_incident = incident
            state.last_incident = incident
            incidents.append(incident)

    def _on_success(self, event: AuthEvent, state: _IpState) -> None:
        incident = state.last_incident
        if incident is None or incident.compromised_user is not None:
            return
        gap = (event.timestamp - incident.last_seen).total_seconds()
        if 0 <= gap <= self.correlation:
            incident.compromised_user = event.user

    @staticmethod
    def _absorb(incident: Incident, event: AuthEvent) -> None:
        incident.attempts += 1
        incident.first_seen = min(incident.first_seen, event.timestamp)
        incident.last_seen = max(incident.last_seen, event.timestamp)
        incident.usernames.add(event.user)
        incident.hosts.add(event.host)
        if event.invalid_user:
            incident.invalid_user_attempts += 1
