import ipaddress
import unittest

from detector import LogAnalyzer
from generator import DOCUMENTATION_NETWORKS, ScenarioGenerator


class ScenarioGeneratorTests(unittest.TestCase):
    def test_same_seed_is_reproducible(self):
        self.assertEqual(
            ScenarioGenerator(2718).generate(4, 2),
            ScenarioGenerator(2718).generate(4, 2),
        )

    def test_generated_attacks_are_detectable_and_use_documentation_ranges(self):
        networks = tuple(ipaddress.ip_network(network) for network in DOCUMENTATION_NETWORKS)
        for seed in range(32):
            with self.subTest(seed=seed):
                scenario = ScenarioGenerator(seed).generate(5, 1)
                self.assertEqual(
                    LogAnalyzer().suspicious_sources(scenario.events),
                    scenario.malicious_ips,
                )
                self.assertTrue(
                    all(
                        any(address in network for network in networks)
                        for address in {event.source_ip for event in scenario.events}
                    )
                )
                self.assertEqual(
                    scenario.events,
                    tuple(sorted(scenario.events, key=lambda event: event.timestamp)),
                )

    def test_difficulty_increases_log_volume_and_threat_count_is_bounded(self):
        generator = ScenarioGenerator(17)
        easy = generator.generate(1)
        harder = generator.generate(4)
        maxed = generator.generate(10)

        self.assertGreater(len(harder.events), len(easy.events))
        self.assertGreater(len(harder.malicious_ips), len(easy.malicious_ips))
        self.assertEqual(len(maxed.malicious_ips), 4)

    def test_invalid_difficulty_and_incident_number_are_rejected(self):
        generator = ScenarioGenerator(1)
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                generator.generate(value)
        with self.assertRaisesRegex(ValueError, "Incident number"):
            generator.generate(1, 0)
        with self.assertRaisesRegex(ValueError, "Incident number"):
            generator.generate(1, 10**20)
        with self.assertRaisesRegex(ValueError, "between 1 and 10"):
            generator.generate(11)


if __name__ == "__main__":
    unittest.main()
