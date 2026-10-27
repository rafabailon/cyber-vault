"""Typed domain models for the isolated incident-response simulator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import ipaddress
from typing import TypeAlias

IPAddress: TypeAlias = ipaddress.IPv4Address
MAX_DIFFICULTY = 10


class EventType(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    TRAFFIC_ANOMALY = "traffic_anomaly"
    PORT_PROBE = "port_probe"
    WEB_ATTACK = "web_attack"
    SYSTEM_ALERT = "system_alert"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class LogEntry:
    """One synthetic, immutable security-log record."""

    timestamp: datetime
    source_ip: IPAddress
    event_type: EventType
    severity: Severity
    message: str
    destination_port: int | None = None
    username: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp, datetime):
            raise ValueError("Log timestamp must be a datetime.")
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("Log timestamps must be timezone-aware.")
        if not isinstance(self.source_ip, ipaddress.IPv4Address):
            raise ValueError("Log source addresses must be IPv4.")
        if not isinstance(self.event_type, EventType):
            raise ValueError("Log event type must be a supported EventType.")
        if not isinstance(self.severity, Severity):
            raise ValueError("Log severity must be a supported Severity.")
        if self.destination_port is not None and (
            isinstance(self.destination_port, bool)
            or not isinstance(self.destination_port, int)
            or not 1 <= self.destination_port <= 65535
        ):
            raise ValueError("Destination port must be an integer between 1 and 65535.")
        if not isinstance(self.message, str) or not self.message.strip():
            raise ValueError("Log message must not be empty.")


@dataclass(frozen=True, slots=True)
class Finding:
    """A detector rule result with evidence visible to the analyst."""

    source_ip: IPAddress
    rule_id: str
    title: str
    evidence: str
    confidence: int

    def __post_init__(self) -> None:
        if not isinstance(self.source_ip, ipaddress.IPv4Address):
            raise ValueError("Finding source address must be IPv4.")
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, int)
            or not 1 <= self.confidence <= 100
        ):
            raise ValueError("Finding confidence must be between 1 and 100.")
        if any(
            not isinstance(value, str) or not value.strip()
            for value in (self.rule_id, self.title, self.evidence)
        ):
            raise ValueError("Finding rule ID, title, and evidence must not be empty.")


@dataclass(frozen=True, slots=True)
class Scenario:
    """A generated exercise; answer keys stay out of user-facing output."""

    difficulty: int
    events: tuple[LogEntry, ...]
    malicious_ips: frozenset[IPAddress]
    incident_id: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.difficulty, bool)
            or not isinstance(self.difficulty, int)
            or not 1 <= self.difficulty <= MAX_DIFFICULTY
        ):
            raise ValueError(f"Difficulty must be between 1 and {MAX_DIFFICULTY}.")
        if not isinstance(self.incident_id, str) or not self.incident_id.strip():
            raise ValueError("Incident ID must not be empty.")
        if not isinstance(self.events, tuple) or not self.events:
            raise ValueError("A scenario must contain at least one event.")
        if not isinstance(self.malicious_ips, frozenset) or not self.malicious_ips:
            raise ValueError("A scenario must contain at least one simulated threat.")
        if not all(isinstance(event, LogEntry) for event in self.events):
            raise ValueError("Scenario events must contain only LogEntry records.")
        if not all(
            isinstance(address, ipaddress.IPv4Address)
            for address in self.malicious_ips
        ):
            raise ValueError("Simulated threat addresses must be IPv4.")
        if not self.malicious_ips.issubset({event.source_ip for event in self.events}):
            raise ValueError("Every simulated threat must appear in the event log.")
        if tuple(sorted(self.events, key=lambda item: item.timestamp)) != self.events:
            raise ValueError("Scenario events must be ordered by timestamp.")

    @property
    def compromised(self) -> bool:
        """Whether this exercise includes a simulated integrity incident."""
        return any(event.event_type is EventType.WEB_ATTACK for event in self.events)


def parse_ipv4(value: str) -> IPAddress:
    """Parse one strict IPv4 address and provide a consistent validation error."""
    if not isinstance(value, str):
        raise ValueError(f"Invalid IPv4 address: {value!r}.")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise ValueError(f"Invalid IPv4 address: {value!r}.") from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 addresses are supported.")
    return address
