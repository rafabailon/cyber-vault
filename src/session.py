"""Game session state, scoring, and safe simulated response actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic
from typing import Callable

from detector import LogAnalyzer
from firewall import VirtualFirewall
from models import (
    EventType,
    Finding,
    IPAddress,
    LogEntry,
    Scenario,
    Severity,
    parse_ipv4,
)

Clock = Callable[[], float]


@dataclass(slots=True)
class ScoreBoard:
    points: int = 0
    incidents_resolved: int = 0
    true_positives: int = 0
    false_positives: int = 0

    @property
    def precision(self) -> float:
        if self.true_positives + self.false_positives == 0:
            return 1.0
        return self.true_positives / (self.true_positives + self.false_positives)


@dataclass(frozen=True, slots=True)
class ActionResult:
    success: bool
    message: str


@dataclass(slots=True)
class IncidentSession:
    scenario: Scenario
    analyzer: LogAnalyzer = field(default_factory=LogAnalyzer)
    firewall: VirtualFirewall = field(default_factory=VirtualFirewall)
    clock: Clock = monotonic
    base_points: int = 100
    _started_at: float = field(init=False, repr=False)
    _restored: bool = field(default=False, init=False, repr=False)
    _resolved: bool = field(default=False, init=False, repr=False)
    _finished_at: float | None = field(default=None, init=False, repr=False)
    _restoration_awarded: bool = field(default=False, init=False, repr=False)
    _penalty: int = field(default=0, init=False, repr=False)
    _earned: int = field(default=0, init=False, repr=False)
    _scored_blocks: set[IPAddress] = field(default_factory=set, init=False, repr=False)
    _findings: tuple[Finding, ...] = field(default=(), init=False, repr=False)
    _source_addresses: frozenset[IPAddress] = field(
        default_factory=frozenset, init=False, repr=False
    )
    scoreboard: ScoreBoard = field(default_factory=ScoreBoard)

    def __post_init__(self) -> None:
        if not isinstance(self.scenario, Scenario):
            raise ValueError("Scenario must be a valid Scenario instance.")
        if (
            isinstance(self.base_points, bool)
            or not isinstance(self.base_points, int)
            or self.base_points < 1
        ):
            raise ValueError("Base points must be a positive integer.")
        if not callable(self.clock):
            raise ValueError("Clock must be callable.")
        self._started_at = self.clock()
        # Scenarios are immutable, so detection results can be reused safely.
        self._findings = self.analyzer.analyze(self.scenario.events)
        self._source_addresses = frozenset(
            event.source_ip for event in self.scenario.events
        )

    @property
    def findings(self) -> tuple[Finding, ...]:
        return self._findings

    @property
    def evidence_sources(self) -> frozenset[IPAddress]:
        """Source addresses supported by at least one explainable finding."""
        return frozenset(finding.source_ip for finding in self._findings)

    @property
    def blocked_ips(self) -> frozenset[IPAddress]:
        return self.firewall.blocked

    @property
    def elapsed_seconds(self) -> float:
        end_time = self._finished_at if self._finished_at is not None else self.clock()
        return max(0.0, end_time - self._started_at)

    @property
    def integrity_restored(self) -> bool:
        return self._restored

    @property
    def resolved(self) -> bool:
        return self._resolved

    @property
    def current_score(self) -> int:
        time_penalty = int(self.elapsed_seconds // 10)
        return max(0, self.base_points + self._earned - self._penalty - time_penalty)

    def filter_events(
        self,
        event_type: str | None = None,
        source_ip: str | None = None,
        minimum_severity: str | None = None,
    ) -> tuple[LogEntry, ...]:
        """Return events matching all supplied filters; invalid filters raise ValueError."""
        selected_type: EventType | None = None
        if event_type:
            try:
                selected_type = EventType(event_type.lower())
            except ValueError as error:
                valid = ", ".join(item.value for item in EventType)
                raise ValueError(f"Unknown event type. Choose from: {valid}.") from error

        address = parse_ipv4(source_ip) if source_ip else None
        severity_rank = None
        if minimum_severity:
            severity_order = list(Severity)
            try:
                severity_rank = severity_order.index(Severity[minimum_severity.upper()])
            except KeyError as error:
                raise ValueError(
                    f"Unknown severity. Choose from: {', '.join(item.value for item in Severity)}."
                ) from error

        result: list[LogEntry] = []
        severity_order = list(Severity)
        for event in self.scenario.events:
            if selected_type is not None and event.event_type is not selected_type:
                continue
            if address is not None and event.source_ip != address:
                continue
            if severity_rank is not None and severity_order.index(event.severity) < severity_rank:
                continue
            result.append(event)
        return tuple(result)

    def block(self, address_text: str) -> ActionResult:
        if self._resolved:
            return ActionResult(False, "This incident is already resolved.")
        try:
            address = parse_ipv4(address_text)
        except ValueError as error:
            return ActionResult(False, str(error))
        if address not in self._source_addresses:
            return ActionResult(False, "That address does not appear in this incident's logs.")
        if not self.firewall.block(address):
            return ActionResult(False, f"{address} is already blocked.")
        if address in self.scenario.malicious_ips:
            self._earned += 20
            self._scored_blocks.add(address)
            self.scoreboard.true_positives += 1
            return ActionResult(True, f"Virtual firewall blocked {address}. Good identification.")
        self._penalty += 25
        self.scoreboard.false_positives += 1
        return ActionResult(
            True,
            f"Virtual firewall blocked {address}. False positive: 25 points deducted.",
        )

    def block_all_malicious(self) -> ActionResult:
        """Block every simulated malicious source in one operation."""
        if self._resolved:
            return ActionResult(False, "This incident is already resolved.")
        blocked_now = 0
        for address in sorted(self.scenario.malicious_ips, key=str):
            if address in self.firewall.blocked:
                continue
            if self.firewall.block(address):
                self._earned += 20
                self._scored_blocks.add(address)
                self.scoreboard.true_positives += 1
                blocked_now += 1
        if blocked_now == 0:
            return ActionResult(True, "All simulated threats are already blocked.")
        return ActionResult(
            True,
            f"Virtual firewall blocked {blocked_now} simulated threat(s). "
            "Good identification.",
        )

    def unblock(self, address_text: str) -> ActionResult:
        if self._resolved:
            return ActionResult(False, "This incident is already resolved.")
        try:
            address = parse_ipv4(address_text)
        except ValueError as error:
            return ActionResult(False, str(error))
        if not self.firewall.unblock(address):
            return ActionResult(False, f"{address} is not currently blocked.")
        if address in self._scored_blocks:
            self._scored_blocks.remove(address)
            self._earned -= 20
            self.scoreboard.true_positives -= 1
            self._restored = False
        elif address not in self.scenario.malicious_ips:
            self._penalty = max(0, self._penalty - 25)
            self.scoreboard.false_positives = max(0, self.scoreboard.false_positives - 1)
        return ActionResult(True, f"Virtual firewall unblocked {address}.")

    def restore(self) -> ActionResult:
        if self._resolved:
            return ActionResult(False, "This incident is already resolved.")
        if self._restored:
            return ActionResult(True, "System integrity was already restored.")
        if not self.scenario.compromised:
            self._restored = True
            return ActionResult(True, "Integrity check passed; no restoration was required.")
        missing = self.scenario.malicious_ips - self.firewall.blocked
        if missing:
            return ActionResult(
                False,
                "Restoration denied: contain all identified sources first "
                f"({len(missing)} remain).",
            )
        self._restored = True
        if not self._restoration_awarded:
            self._earned += 30
            self._restoration_awarded = True
        return ActionResult(True, "System integrity restored in the isolated simulation.")

    def resolve(self) -> ActionResult:
        if self._resolved:
            return ActionResult(False, "This incident is already resolved.")
        missing = self.scenario.malicious_ips - self.firewall.blocked
        if missing:
            return ActionResult(
                False,
                f"Cannot close incident: {len(missing)} simulated threat(s) remain.",
            )
        if self.scenario.compromised and not self._restored:
            return ActionResult(False, "Restore system integrity before closing this incident.")
        if not self._restored:
            return ActionResult(False, "Run the integrity check before closing this incident.")
        elapsed = self.elapsed_seconds
        speed_bonus = max(0, 30 - int(elapsed // 5))
        self._earned += speed_bonus
        self._resolved = True
        self._finished_at = self.clock()
        final_points = self.current_score
        self.scoreboard.points += final_points
        self.scoreboard.incidents_resolved += 1
        return ActionResult(
            True,
            f"Incident {self.scenario.incident_id} closed. "
            f"Score: {final_points} (+{speed_bonus} speed bonus).",
        )
