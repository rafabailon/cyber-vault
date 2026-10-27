"""Seedable synthetic security-log generation; no network access is performed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random

from branding import INCIDENT_PREFIX
from models import (
    MAX_DIFFICULTY,
    EventType,
    IPAddress,
    LogEntry,
    Scenario,
    Severity,
    parse_ipv4,
)

MAX_INCIDENT_NUMBER = 999_999
DOCUMENTATION_NETWORKS = (
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
)
SUSPICIOUS_WEB_MARKERS = (
    "SIMULATED_SQLI_MARKER",
    "SIMULATED_PATH_TRAVERSAL_MARKER",
    "SIMULATED_TEMPLATE_INJECTION_MARKER",
)
SAFE_LOGIN_MESSAGES = (
    "Successful authentication from approved workstation.",
    "Failed authentication; credentials rejected.",
)
BENIGN_MESSAGES = (
    "Routine health-check request completed.",
    "Scheduled metrics export completed.",
    "User session refreshed successfully.",
    "Static asset request served normally.",
)


class ScenarioGenerator:
    """Create reproducible scenarios from documentation-only IP ranges."""

    def __init__(self, seed: int | None = None) -> None:
        self._random = random.Random(seed)

    def generate(self, difficulty: int, incident_number: int = 1) -> Scenario:
        """Generate one challenge, increasing log volume and threat count."""
        if (
            isinstance(difficulty, bool)
            or not isinstance(difficulty, int)
            or not 1 <= difficulty <= MAX_DIFFICULTY
        ):
            raise ValueError(f"Difficulty must be between 1 and {MAX_DIFFICULTY}.")
        if (
            isinstance(incident_number, bool)
            or not isinstance(incident_number, int)
            or not 1 <= incident_number <= MAX_INCIDENT_NUMBER
        ):
            raise ValueError(
                f"Incident number must be between 1 and {MAX_INCIDENT_NUMBER}."
            )

        attack_count = min(1 + (difficulty - 1) // 2, 4)
        benign_count = 8 + difficulty * 4
        base_time = datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(days=incident_number)
        event_rows: list[LogEntry] = []
        malicious_ips: set[IPAddress] = set()
        used_addresses: set[str] = set()

        for index in range(attack_count):
            address = self._next_ip(used_addresses)
            malicious_ips.add(address)
            attack_type = self._random.choice(
                (
                    EventType.LOGIN_FAILURE,
                    EventType.PORT_PROBE,
                    EventType.TRAFFIC_ANOMALY,
                    EventType.WEB_ATTACK,
                )
            )
            event_rows.extend(self._attack_events(address, attack_type, base_time, index))

        for index in range(benign_count):
            address = self._next_ip(used_addresses, benign=True)
            event_type = self._random.choice(
                (
                    EventType.LOGIN_SUCCESS,
                    EventType.LOGIN_FAILURE,
                    EventType.SYSTEM_ALERT,
                )
            )
            if event_type is EventType.LOGIN_SUCCESS:
                message = SAFE_LOGIN_MESSAGES[0]
            elif event_type is EventType.LOGIN_FAILURE:
                message = SAFE_LOGIN_MESSAGES[1]
            else:
                message = self._random.choice(BENIGN_MESSAGES)
            event_rows.append(
                LogEntry(
                    timestamp=base_time + timedelta(seconds=self._random.randint(0, 240)),
                    source_ip=address,
                    event_type=event_type,
                    severity=Severity.INFO if index % 3 else Severity.LOW,
                    message=message,
                    username=self._random.choice(("analyst", "service", "operator"))
                    if index % 2 == 0
                    else None,
                )
            )

        event_rows.sort(
            key=lambda event: (
                event.timestamp,
                str(event.source_ip),
                event.event_type.value,
            )
        )
        return Scenario(
            difficulty=difficulty,
            events=tuple(event_rows),
            malicious_ips=frozenset(malicious_ips),
            incident_id=f"{INCIDENT_PREFIX}-{incident_number:04d}",
        )

    def _next_ip(self, used: set[str], benign: bool = False) -> IPAddress:
        network = self._random.choice(DOCUMENTATION_NETWORKS)
        octets = network.split(".")
        while True:
            address_text = ".".join((*octets[:3], str(self._random.randint(1, 254))))
            if address_text in used:
                continue
            if benign and address_text.endswith(".1"):
                continue
            used.add(address_text)
            return parse_ipv4(address_text)

    def _attack_events(
        self,
        address: IPAddress,
        attack_type: EventType,
        base_time: datetime,
        offset: int,
    ) -> list[LogEntry]:
        start = base_time + timedelta(seconds=30 + offset * 13)
        records: list[LogEntry] = []
        if attack_type is EventType.LOGIN_FAILURE:
            for attempt in range(6):
                records.append(
                    LogEntry(
                        start + timedelta(seconds=attempt * 5),
                        address,
                        EventType.LOGIN_FAILURE,
                        Severity.MEDIUM,
                        "Repeated authentication failure; credentials rejected.",
                        username=("admin", "root", "analyst")[attempt % 3],
                    )
                )
        elif attack_type is EventType.PORT_PROBE:
            for attempt, port in enumerate((21, 22, 23, 80, 443, 3389)):
                records.append(
                    LogEntry(
                        start + timedelta(seconds=attempt * 3),
                        address,
                        EventType.PORT_PROBE,
                        Severity.LOW,
                        "Synthetic connection probe logged by virtual sensor.",
                        destination_port=port,
                    )
                )
        elif attack_type is EventType.TRAFFIC_ANOMALY:
            for attempt in range(5):
                records.append(
                    LogEntry(
                        start + timedelta(seconds=attempt * 4),
                        address,
                        EventType.TRAFFIC_ANOMALY,
                        Severity.HIGH,
                        "Synthetic request-rate deviation exceeds baseline.",
                    )
                )
        else:
            records.append(
                LogEntry(
                    start,
                    address,
                    EventType.WEB_ATTACK,
                    Severity.HIGH,
                    "Simulated suspicious request marker: "
                    f"{self._random.choice(SUSPICIOUS_WEB_MARKERS)}.",
                )
            )
        return records
