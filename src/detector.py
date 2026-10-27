"""Explainable threshold-based detections for synthetic event streams."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from models import EventType, Finding, IPAddress, LogEntry


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    failed_logins: int = 4
    distinct_ports: int = 5
    anomalous_requests: int = 4

    def __post_init__(self) -> None:
        for name, value in (
            ("failed_logins", self.failed_logins),
            ("distinct_ports", self.distinct_ports),
            ("anomalous_requests", self.anomalous_requests),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer.")


class LogAnalyzer:
    """Apply transparent rules and return source-attributed evidence."""

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()

    def analyze(self, events: tuple[LogEntry, ...] | list[LogEntry]) -> tuple[Finding, ...]:
        by_source: dict[IPAddress, list[LogEntry]] = defaultdict(list)
        for event in events:
            by_source[event.source_ip].append(event)

        findings: list[Finding] = []
        for address, source_events in by_source.items():
            failed_logins = 0
            probed_ports: set[int] = set()
            anomalies = 0
            web_attack_seen = False

            # One pass per source keeps detection linear in the number of events.
            for event in source_events:
                if event.event_type is EventType.LOGIN_FAILURE:
                    failed_logins += 1
                elif event.event_type is EventType.PORT_PROBE:
                    if event.destination_port is not None:
                        probed_ports.add(event.destination_port)
                elif event.event_type is EventType.TRAFFIC_ANOMALY:
                    anomalies += 1
                elif event.event_type is EventType.WEB_ATTACK:
                    web_attack_seen = True

            if failed_logins >= self.config.failed_logins:
                findings.append(
                    Finding(
                        address,
                        "AUTH-001",
                        "Repeated authentication failures",
                        f"{failed_logins} failed logins; threshold is {self.config.failed_logins}.",
                        min(100, 70 + failed_logins * 3),
                    )
                )

            if len(probed_ports) >= self.config.distinct_ports:
                findings.append(
                    Finding(
                        address,
                        "NET-002",
                        "Multiple destination ports probed",
                        f"{len(probed_ports)} distinct ports observed; "
                        f"threshold is {self.config.distinct_ports}.",
                        min(100, 72 + len(probed_ports) * 3),
                    )
                )

            if anomalies >= self.config.anomalous_requests:
                findings.append(
                    Finding(
                        address,
                        "NET-003",
                        "Traffic deviates from baseline",
                        f"{anomalies} anomaly markers observed; "
                        f"threshold is {self.config.anomalous_requests}.",
                        min(100, 72 + anomalies * 4),
                    )
                )

            if web_attack_seen:
                findings.append(
                    Finding(
                        address,
                        "WEB-004",
                        "Simulated suspicious web request",
                        "A non-executable training marker was recorded "
                        "in the synthetic access log.",
                        95,
                    )
                )

        return tuple(sorted(findings, key=lambda item: (str(item.source_ip), item.rule_id)))

    def suspicious_sources(
        self,
        events: tuple[LogEntry, ...] | list[LogEntry],
    ) -> frozenset[IPAddress]:
        """Return unique source addresses with at least one rule hit."""
        return frozenset(finding.source_ip for finding in self.analyze(events))
