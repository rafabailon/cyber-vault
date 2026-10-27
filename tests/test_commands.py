import unittest

from commands import CommandProcessor
from generator import ScenarioGenerator
from session import IncidentSession


class CommandProcessorTests(unittest.TestCase):
    def setUp(self):
        self.session = IncidentSession(ScenarioGenerator(4).generate(2))
        self.commands = CommandProcessor(self.session)

    def test_help_status_and_empty_command(self):
        self.assertEqual(self.commands.execute("").message, "")
        self.assertIn("Available commands", self.commands.execute("help").message)
        self.assertIn("Incident:", self.commands.execute("status").message)

    def test_logs_filters_validate_and_display_synthetic_data(self):
        output = self.commands.execute("logs severity=HIGH")
        self.assertTrue(
            output.message.startswith(("Showing ", "No log entries"))
        )
        if output.message.startswith("Showing "):
            self.assertIn("synthetic events", output.message)
        self.assertIn("Invalid filter", self.commands.execute("logs typo").message)
        self.assertIn("Unknown log filter", self.commands.execute("logs nope=x").message)
        duplicate = self.commands.execute("logs ip=192.0.2.1 ip=192.0.2.2")
        self.assertIn("more than once", duplicate.message)
        self.assertIn("requires a value", self.commands.execute("logs type=").message)
        self.assertIn("Unknown event type", self.commands.execute("logs type=exploit").message)

    def test_analysis_and_command_argument_validation(self):
        self.assertIn("finding", self.commands.execute("analyze").message)
        self.assertIn("Usage", self.commands.execute("block").message)
        self.assertIn("Unexpected arguments", self.commands.execute("analyze extra").message)
        self.assertIn("Unknown command", self.commands.execute("execute something").message)
        self.assertIn("Could not parse", self.commands.execute('"unterminated').message)

    def test_response_and_exit_commands(self):
        restore_result = self.commands.execute("restore")
        self.assertTrue(
            restore_result.message.startswith(
                ("Restoration denied", "Integrity check passed")
            )
        )
        address = str(next(iter(self.session.scenario.malicious_ips)))
        self.assertIn("blocked", self.commands.execute(f"block {address}").message)
        self.assertIn("unblocked", self.commands.execute(f"unblock {address}").message)
        self.assertFalse(self.commands.execute("close").incident_closed)
        quit_result = self.commands.execute("quit")
        self.assertTrue(quit_result.should_quit)
        self.assertIn("No real systems", quit_result.message)

    def test_log_commands_support_quoted_filter_values(self):
        result = self.commands.execute('logs "severity=high"')
        self.assertTrue(result.message.startswith(("Showing ", "No log entries")))


if __name__ == "__main__":
    unittest.main()
