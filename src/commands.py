"""Safe command parsing and analyst-facing output formatting."""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from models import LogEntry
from session import ActionResult, IncidentSession


HELP_TEXT = """Available commands:
  help                         Show this command reference
  logs [type=TYPE] [ip=IP] [severity=LEVEL]
                               Inspect or filter synthetic logs
  analyze                      Run explainable detection rules
  block IP                     Add an IP to the virtual firewall
  unblock IP                   Remove an IP from the virtual firewall
  restore                      Run the simulated integrity-restoration step
  status                       Show containment and score status
  close                        Close the incident when all objectives are met
  quit                         Leave the simulator

Log types: login_success, login_failure, traffic_anomaly, port_probe,
           web_attack, system_alert
Severity levels: INFO, LOW, MEDIUM, HIGH, CRITICAL
All actions affect this local simulation only; no network traffic is sent."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    message: str
    should_quit: bool = False
    incident_closed: bool = False


class CommandProcessor:
    """Validate analyst commands before applying in-memory simulation actions."""

    def __init__(self, session: IncidentSession) -> None:
        self.session = session

    def execute(self, raw_command: str) -> CommandResult:
        try:
            tokens = shlex.split(raw_command)
        except ValueError as error:
            return CommandResult(f"Could not parse command: {error}")
        if not tokens:
            return CommandResult("")

        command = tokens[0].lower()
        if command == "help" and len(tokens) == 1:
            return CommandResult(HELP_TEXT)
        if command == "quit" and len(tokens) == 1:
            return CommandResult(
                "Leaving the simulator. No real systems were changed.",
                should_quit=True,
            )
        if command == "logs":
            return self._logs(tokens[1:])
        if command == "analyze" and len(tokens) == 1:
            return self._analyze()
        if command == "block" and len(tokens) == 2:
            return self._action(self.session.block(tokens[1]))
        if command == "unblock" and len(tokens) == 2:
            return self._action(self.session.unblock(tokens[1]))
        if command == "restore" and len(tokens) == 1:
            return self._action(self.session.restore())
        if command == "status" and len(tokens) == 1:
            return self._status()
        if command == "close" and len(tokens) == 1:
            result = self.session.resolve()
            return CommandResult(result.message, incident_closed=result.success)
        if command in {"block", "unblock"}:
            return CommandResult(f"Usage: {command} IPv4_ADDRESS")
        if command in {"help", "analyze", "restore", "status", "close", "quit"}:
            return CommandResult(f"Unexpected arguments for {command}. Type 'help' for usage.")
        return CommandResult(
            f"Unknown command: {tokens[0]!r}. Type 'help' for available commands."
        )

    def _logs(self, filters: list[str]) -> CommandResult:
        selected: dict[str, str] = {}
        allowed = {"type", "ip", "severity"}
        for item in filters:
            if "=" not in item:
                return CommandResult(f"Invalid filter {item!r}; use key=value.")
            key, value = item.split("=", 1)
            key = key.lower()
            if key not in allowed:
                return CommandResult(
                    f"Unknown log filter {key!r}. Allowed filters: type, ip, severity."
                )
            if key in selected:
                return CommandResult(f"Filter {key!r} was specified more than once.")
            if not value:
                return CommandResult(f"Filter {key!r} requires a value.")
            selected[key] = value

        try:
            events = self.session.filter_events(
                event_type=selected.get("type"),
                source_ip=selected.get("ip"),
                minimum_severity=selected.get("severity"),
            )
        except ValueError as error:
            return CommandResult(str(error))
        if not events:
            return CommandResult("No log entries matched those filters.")
        lines = [
            f"Showing {len(events)} of {len(self.session.scenario.events)} synthetic events:"
        ]
        lines.extend(_format_event(event) for event in events)
        return CommandResult("\n".join(lines))

    def _analyze(self) -> CommandResult:
        findings = self.session.findings
        if not findings:
            return CommandResult("No detection rules fired. Continue reviewing the logs.")
        lines = [f"Analysis produced {len(findings)} finding(s):"]
        lines.extend(
            f"  [{finding.rule_id}] {finding.source_ip} — {finding.title} "
            f"({finding.confidence}% confidence)\n"
            f"      Evidence: {finding.evidence}"
            for finding in findings
        )
        lines.append("Review the evidence before adding virtual firewall rules.")
        return CommandResult("\n".join(lines))

    def _status(self) -> CommandResult:
        scenario = self.session.scenario
        return CommandResult(
            f"Incident: {scenario.incident_id} | Difficulty: {scenario.difficulty} | "
            f"Events: {len(scenario.events)}\n"
            f"Virtual firewall rules: {len(self.session.blocked_ips)} | "
            f"Integrity restored: {'yes' if self.session.integrity_restored else 'no'}\n"
            f"Elapsed: {self.session.elapsed_seconds:.1f}s | "
            f"Current score: {self.session.current_score}"
        )

    @staticmethod
    def _action(result: ActionResult) -> CommandResult:
        return CommandResult(result.message)


def _format_event(event: LogEntry) -> str:
    port = f":{event.destination_port}" if event.destination_port is not None else ""
    user = f" user={event.username}" if event.username else ""
    return (
        f"  {event.timestamp.isoformat(timespec='seconds')} "
        f"{event.severity.value:<8} {event.source_ip}{port:<6} "
        f"{event.event_type.value:<16}{user} — {event.message}"
    )
