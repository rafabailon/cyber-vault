import io
import subprocess
import sys
import unittest
from pathlib import Path

from branding import APP_NAME, PROMPT, VERSION
from cyber_vault import main
from generator import ScenarioGenerator

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


class CliTests(unittest.TestCase):
    def test_cli_runs_complete_seeded_incident(self):
        seed = 88
        generator = ScenarioGenerator(seed)
        commands = []
        for round_number in (1, 2):
            scenario = generator.generate(round_number, round_number)
            commands.append("analyze")
            commands.extend(f"block {address}" for address in scenario.malicious_ips)
            commands.extend(("restore", "close"))
        output = io.StringIO()

        status = main(
            ["--seed", str(seed), "--rounds", "2"],
            input_stream=io.StringIO("\n".join(commands) + "\n"),
            output_stream=output,
        )

        self.assertEqual(status, 0)
        self.assertIn("Training complete", output.getvalue())
        self.assertIn("2/2 incidents resolved", output.getvalue())
        self.assertIn("difficulty 2", output.getvalue())
        self.assertTrue(output.getvalue().startswith("CYBER VAULT //"))
        self.assertIn(PROMPT, output.getvalue())
        self.assertEqual(APP_NAME, "Cyber Vault")

    def test_direct_script_runs_and_closes_a_seeded_incident(self):
        seed = 213
        scenario = ScenarioGenerator(seed).generate(1, 1)
        commands = ["analyze"]
        commands.extend(f"block {address}" for address in scenario.malicious_ips)
        commands.extend(("restore", "close"))
        completed = subprocess.run(
            [
                sys.executable,
                str(SRC / "cyber_vault.py"),
                "--seed",
                str(seed),
                "--rounds",
                "1",
            ],
            cwd=ROOT,
            env={"PYTHONPATH": str(SRC)},
            input="\n".join(commands) + "\n",
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Incident CV-0001 closed", completed.stdout)
        self.assertIn("Training complete", completed.stdout)

    def test_quit_and_eof_exit_cleanly(self):
        quit_output = io.StringIO()
        self.assertEqual(
            main(["--rounds", "2"], io.StringIO("quit\n"), quit_output),
            0,
        )
        self.assertIn("Leaving the simulator", quit_output.getvalue())
        eof_output = io.StringIO()
        self.assertEqual(main(["--rounds", "1"], io.StringIO(""), eof_output), 0)
        self.assertIn("Input ended", eof_output.getvalue())

    def test_keyboard_interrupt_exits_without_traceback(self):
        class InterruptedInput:
            def readline(self):
                raise KeyboardInterrupt

        output = io.StringIO()
        status = main(["--rounds", "1"], InterruptedInput(), output)

        self.assertEqual(status, 130)
        self.assertIn("No real systems were changed", output.getvalue())

    def test_cli_help_and_invalid_bounds(self):
        help_result = subprocess.run(
            [sys.executable, str(SRC / "cyber_vault.py"), "--help"],
            cwd=ROOT,
            env={"PYTHONPATH": str(SRC)},
            capture_output=True,
            text=True,
            check=False,
        )
        version_result = subprocess.run(
            [sys.executable, str(SRC / "cyber_vault.py"), "--version"],
            cwd=ROOT,
            env={"PYTHONPATH": str(SRC)},
            capture_output=True,
            text=True,
            check=False,
        )
        invalid_result = subprocess.run(
            [sys.executable, str(SRC / "cyber_vault.py"), "--rounds", "0"],
            cwd=ROOT,
            env={"PYTHONPATH": str(SRC)},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("never accesses a network", help_result.stdout)
        self.assertIn("cyber-vault", help_result.stdout)
        self.assertEqual(version_result.returncode, 0)
        self.assertIn(f"{APP_NAME} {VERSION}", version_result.stdout)
        self.assertEqual(invalid_result.returncode, 2)
        self.assertIn("between 1 and 10", invalid_result.stderr)


if __name__ == "__main__":
    unittest.main()
