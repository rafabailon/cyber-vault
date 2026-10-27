import unittest
from datetime import datetime, timedelta
import ipaddress

from models import EventType, Finding, LogEntry, Scenario, Severity, parse_ipv4


def sample_event():
    return LogEntry(
        datetime.fromisoformat("2025-01-01T00:00:00+00:00"),
        ipaddress.IPv4Address("192.0.2.10"),
        EventType.LOGIN_SUCCESS,
        Severity.INFO,
        "Synthetic successful login.",
    )


class ModelTests(unittest.TestCase):
    def test_log_entry_requires_aware_timestamp_and_valid_port(self):
        event = sample_event()
        self.assertEqual(event.source_ip, ipaddress.IPv4Address("192.0.2.10"))
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            LogEntry(
                datetime(2025, 1, 1),
                event.source_ip,
                event.event_type,
                event.severity,
                "message",
            )
        with self.assertRaisesRegex(ValueError, "port"):
            LogEntry(
                event.timestamp,
                event.source_ip,
                EventType.PORT_PROBE,
                Severity.LOW,
                "probe",
                destination_port=70000,
            )

    def test_log_entry_rejects_empty_message_and_ipv6(self):
        event = sample_event()
        with self.assertRaisesRegex(ValueError, "message"):
            LogEntry(
                event.timestamp,
                event.source_ip,
                event.event_type,
                event.severity,
                "   ",
            )
        with self.assertRaisesRegex(ValueError, "IPv4"):
            LogEntry(
                event.timestamp,
                ipaddress.IPv6Address("2001:db8::1"),
                event.event_type,
                event.severity,
                "message",
            )
        with self.assertRaisesRegex(ValueError, "supported EventType"):
            LogEntry(
                event.timestamp,
                event.source_ip,
                "login_success",
                event.severity,
                "message",
            )
        with self.assertRaisesRegex(ValueError, "integer between"):
            LogEntry(
                event.timestamp,
                event.source_ip,
                EventType.PORT_PROBE,
                Severity.LOW,
                "probe",
                destination_port=True,
            )

    def test_finding_confidence_must_be_an_integer_percentage(self):
        address = ipaddress.IPv4Address("192.0.2.10")
        for confidence in (0, 101, True, 1.5):
            with self.subTest(confidence=confidence), self.assertRaises(ValueError):
                Finding(address, "TEST", "Test finding", "Synthetic evidence.", confidence)
        with self.assertRaisesRegex(ValueError, "source address must be IPv4"):
            Finding(
                ipaddress.IPv6Address("2001:db8::1"),
                "TEST",
                "Test finding",
                "Synthetic evidence.",
                90,
            )
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            Finding(address, " ", "Test finding", "Synthetic evidence.", 90)

    def test_scenario_requires_valid_sorted_events_and_threats(self):
        event = sample_event()
        attacker = ipaddress.IPv4Address("192.0.2.10")
        self.assertFalse(Scenario(1, (event,), frozenset({attacker}), "CV-0001").compromised)
        with self.assertRaisesRegex(ValueError, "at least one event"):
            Scenario(1, (), frozenset({attacker}), "CV-0001")
        with self.assertRaisesRegex(ValueError, "at least one simulated threat"):
            Scenario(1, (event,), frozenset(), "CV-0001")
        with self.assertRaisesRegex(ValueError, "Incident ID"):
            Scenario(1, (event,), frozenset({attacker}), None)
        with self.assertRaisesRegex(ValueError, "only LogEntry"):
            Scenario(1, ("not a log",), frozenset({attacker}), "CV-0001")
        with self.assertRaisesRegex(ValueError, "must be IPv4"):
            Scenario(
                1,
                (event,),
                frozenset({ipaddress.IPv6Address("2001:db8::1")}),
                "CV-0001",
            )
        with self.assertRaisesRegex(ValueError, "between 1 and 10"):
            Scenario(11, (event,), frozenset({attacker}), "CV-0001")
        later = LogEntry(
            event.timestamp + timedelta(minutes=1),
            event.source_ip,
            event.event_type,
            event.severity,
            event.message,
        )
        with self.assertRaisesRegex(ValueError, "ordered"):
            Scenario(1, (later, event), frozenset({attacker}), "CV-0001")

    def test_parse_ipv4_strips_whitespace_and_rejects_invalid_and_ipv6(self):
        self.assertEqual(parse_ipv4(" 198.51.100.7 "), ipaddress.IPv4Address("198.51.100.7"))
        with self.assertRaisesRegex(ValueError, "Invalid IPv4"):
            parse_ipv4("not-an-address")
        with self.assertRaisesRegex(ValueError, "Only IPv4"):
            parse_ipv4("2001:db8::2")
        with self.assertRaisesRegex(ValueError, "Invalid IPv4"):
            parse_ipv4(None)


if __name__ == "__main__":
    unittest.main()
