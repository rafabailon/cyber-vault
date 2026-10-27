import unittest

from generator import ScenarioGenerator
from models import EventType
from session import IncidentSession, ScoreBoard


class FakeClock:
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def scenario_with_web_attack():
    for seed in range(100):
        scenario = ScenarioGenerator(seed).generate(1)
        if scenario.compromised:
            return scenario
    raise AssertionError("Expected at least one seeded web-attack scenario.")


def scenario_without_web_attack():
    for seed in range(100):
        scenario = ScenarioGenerator(seed).generate(1)
        if not scenario.compromised:
            return scenario
    raise AssertionError("Expected at least one seeded non-web scenario.")


class IncidentSessionTests(unittest.TestCase):
    def test_filtering_by_event_source_and_severity(self):
        session = IncidentSession(ScenarioGenerator(12).generate(2))
        failures = session.filter_events(event_type="login_failure")
        self.assertTrue(all(event.event_type is EventType.LOGIN_FAILURE for event in failures))
        if failures:
            address = str(failures[0].source_ip)
            filtered = session.filter_events(source_ip=address)
            self.assertTrue(
                all(event.source_ip == failures[0].source_ip for event in filtered)
            )
        high = session.filter_events(minimum_severity="HIGH")
        self.assertTrue(all(event.severity.value in {"HIGH", "CRITICAL"} for event in high))
        with self.assertRaisesRegex(ValueError, "Unknown event type"):
            session.filter_events(event_type="untrusted")
        with self.assertRaisesRegex(ValueError, "Unknown severity"):
            session.filter_events(minimum_severity="URGENT")
        with self.assertRaisesRegex(ValueError, "Invalid IPv4"):
            session.filter_events(source_ip="not-ip")

    def test_false_positive_cost_can_be_reversed_by_unblocking(self):
        scenario = scenario_with_web_attack()
        false_positive = next(
            event.source_ip
            for event in scenario.events
            if event.source_ip not in scenario.malicious_ips
        )
        session = IncidentSession(scenario)

        result = session.block(str(false_positive))
        self.assertIn("False positive", result.message)
        self.assertEqual(session.current_score, 75)
        self.assertEqual(session.scoreboard.false_positives, 1)
        session.unblock(str(false_positive))
        self.assertEqual(session.current_score, 100)
        self.assertEqual(session.scoreboard.false_positives, 0)

    def test_invalid_duplicate_and_nonincident_blocks_are_rejected(self):
        session = IncidentSession(ScenarioGenerator(3).generate(1))
        attacker = str(next(iter(session.scenario.malicious_ips)))

        self.assertFalse(session.block("invalid").success)
        self.assertFalse(session.block("8.8.8.8").success)
        self.assertTrue(session.block(attacker).success)
        self.assertFalse(session.block(attacker).success)
        self.assertFalse(session.unblock("not-an-ip").success)

    def test_restoration_requires_containment_and_incident_close_requires_restore(self):
        scenario = scenario_with_web_attack()
        clock = FakeClock()
        session = IncidentSession(scenario, clock=clock)

        self.assertFalse(session.restore().success)
        self.assertFalse(session.resolve().success)
        for address in scenario.malicious_ips:
            session.block(str(address))
        first_restore = session.restore()
        self.assertTrue(first_restore.success)
        score_after_restore = session.current_score
        duplicate_restore = session.restore()
        self.assertTrue(duplicate_restore.success)
        self.assertIn("already restored", duplicate_restore.message)
        self.assertEqual(session.current_score, score_after_restore)
        address = str(next(iter(scenario.malicious_ips)))
        session.unblock(address)
        self.assertFalse(session.integrity_restored)
        session.block(address)
        self.assertTrue(session.restore().success)
        self.assertEqual(session.current_score, score_after_restore)
        self.assertTrue(session.resolve().success)
        self.assertFalse(session.resolve().success)
        self.assertFalse(session.restore().success)
        self.assertFalse(
            session.unblock(str(next(iter(scenario.malicious_ips)))).success
        )
        self.assertEqual(session.scoreboard.incidents_resolved, 1)

    def test_clean_scenario_requires_integrity_check_but_no_restore_bonus(self):
        scenario = scenario_without_web_attack()
        clock = FakeClock()
        session = IncidentSession(scenario, clock=clock)
        for address in scenario.malicious_ips:
            session.block(str(address))
        score_before_check = session.current_score
        self.assertTrue(session.restore().success)
        self.assertEqual(session.current_score, score_before_check)
        self.assertTrue(session.resolve().success)
        self.assertEqual(session.scoreboard.incidents_resolved, 1)

    def test_speed_bonus_and_elapsed_time_score(self):
        scenario = scenario_without_web_attack()
        clock = FakeClock()
        session = IncidentSession(scenario, clock=clock)
        clock.advance(15.0)
        self.assertEqual(session.elapsed_seconds, 15.0)
        self.assertEqual(session.current_score, 99)
        for address in scenario.malicious_ips:
            session.block(str(address))
        session.restore()
        result = session.resolve()
        self.assertIn("speed bonus", result.message)
        self.assertGreater(session.scoreboard.points, 0)
        final_score = session.current_score
        final_elapsed = session.elapsed_seconds
        clock.advance(10_000)
        self.assertEqual(session.current_score, final_score)
        self.assertEqual(session.elapsed_seconds, final_elapsed)
        self.assertEqual(session.scoreboard.points, final_score)

    def test_base_points_must_be_positive(self):
        with self.assertRaisesRegex(ValueError, "Base points"):
            IncidentSession(ScenarioGenerator(1).generate(1), base_points=0)

    def test_block_all_malicious_and_evidence_sources(self):
        scenario = scenario_with_web_attack()
        session = IncidentSession(scenario)
        self.assertGreater(len(session.evidence_sources), 0)
        result = session.block_all_malicious()
        self.assertTrue(result.success)
        self.assertTrue(scenario.malicious_ips.issubset(session.firewall.blocked))
        second = session.block_all_malicious()
        self.assertIn("already blocked", second.message)


if __name__ == "__main__":
    unittest.main()
