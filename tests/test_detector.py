import unittest
from datetime import datetime, timedelta, timezone
import ipaddress

from detector import DetectionConfig, LogAnalyzer
from models import EventType, LogEntry, Severity

BASE = datetime(2025, 1, 1, tzinfo=timezone.utc)
SOURCE = ipaddress.IPv4Address("192.0.2.44")


def event(kind, index=0, port=None, source=SOURCE):
    return LogEntry(
        BASE + timedelta(seconds=index),
        source,
        kind,
        Severity.MEDIUM,
        "Synthetic training record.",
        destination_port=port,
    )


class DetectorTests(unittest.TestCase):
    def test_each_detection_rule_returns_explainable_finding(self):
        analyzer = LogAnalyzer()
        cases = (
            (
                [event(EventType.LOGIN_FAILURE, index) for index in range(4)],
                "AUTH-001",
            ),
            (
                [
                    event(EventType.PORT_PROBE, index, port)
                    for index, port in enumerate((22, 53, 80, 443, 3389))
                ],
                "NET-002",
            ),
            (
                [event(EventType.TRAFFIC_ANOMALY, index) for index in range(4)],
                "NET-003",
            ),
            ([event(EventType.WEB_ATTACK)], "WEB-004"),
        )
        for events, rule in cases:
            with self.subTest(rule=rule):
                findings = analyzer.analyze(events)
                self.assertIn(rule, {finding.rule_id for finding in findings})
                self.assertTrue(all(finding.evidence for finding in findings))
                self.assertTrue(all(1 <= finding.confidence <= 100 for finding in findings))

    def test_below_thresholds_do_not_alert_and_sources_are_deduplicated(self):
        other = ipaddress.IPv4Address("198.51.100.8")
        events = [
            event(EventType.LOGIN_FAILURE, 1),
            event(EventType.PORT_PROBE, 2, 22),
            event(EventType.TRAFFIC_ANOMALY, 3),
            event(EventType.LOGIN_FAILURE, 4, source=other),
        ]
        analyzer = LogAnalyzer()

        self.assertEqual(analyzer.analyze(events), ())
        self.assertEqual(analyzer.suspicious_sources(events), frozenset())

    def test_custom_threshold_configuration_is_validated(self):
        config = DetectionConfig(failed_logins=2, distinct_ports=2, anomalous_requests=2)
        findings = LogAnalyzer(config).analyze(
            [event(EventType.LOGIN_FAILURE, 1), event(EventType.LOGIN_FAILURE, 2)]
        )
        self.assertEqual([finding.rule_id for finding in findings], ["AUTH-001"])
        with self.assertRaisesRegex(ValueError, "positive integer"):
            DetectionConfig(failed_logins=0)
        with self.assertRaisesRegex(ValueError, "positive integer"):
            DetectionConfig(distinct_ports=True)


if __name__ == "__main__":
    unittest.main()
