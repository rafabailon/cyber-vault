"""Terminal entry point for Cyber Vault: Incident Response Simulator."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence, TextIO

from branding import APP_DESCRIPTION, APP_NAME, APP_SLUG, BANNER, PROMPT, VERSION
from commands import CommandProcessor
from generator import ScenarioGenerator
from models import MAX_DIFFICULTY
from session import IncidentSession, ScoreBoard

MAX_ROUNDS = 10


def _bounded_integer(value: str, label: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{label} must be a whole number.") from error
    if not minimum <= parsed <= maximum:
        raise argparse.ArgumentTypeError(
            f"{label} must be between {minimum} and {maximum}."
        )
    return parsed


def _rounds(value: str) -> int:
    return _bounded_integer(value, "Rounds", 1, MAX_ROUNDS)


def _difficulty(value: str) -> int:
    return _bounded_integer(value, "Difficulty", 1, MAX_DIFFICULTY)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_SLUG,
        description=(
            f"{APP_NAME}: {APP_DESCRIPTION} Practice incident analysis and response "
            "against synthetic logs. This simulator never accesses a network."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    parser.add_argument("--seed", type=int, help="seed for repeatable scenarios")
    parser.add_argument("--rounds", type=_rounds, default=3, help="number of incidents (1-10)")
    parser.add_argument(
        "--difficulty",
        type=_difficulty,
        default=1,
        help="starting difficulty (1-10); each round increases it",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    if input_stream is None:
        input_stream = sys.stdin
    if output_stream is None:
        output_stream = sys.stdout
    generator = ScenarioGenerator(args.seed)
    scoreboard = ScoreBoard()
    print(BANNER, file=output_stream)

    for round_number in range(1, args.rounds + 1):
        difficulty = min(MAX_DIFFICULTY, args.difficulty + round_number - 1)
        scenario = generator.generate(difficulty, round_number)
        session = IncidentSession(scenario=scenario, scoreboard=scoreboard)
        processor = CommandProcessor(session)
        print(
            f"\n=== Incident {round_number}/{args.rounds}: {scenario.incident_id} "
            f"| difficulty {difficulty} ===\n"
            f"{len(scenario.events)} synthetic log events. Review, contain, restore, and close.",
            file=output_stream,
        )

        while not session.resolved:
            output_stream.write(PROMPT)
            output_stream.flush()
            try:
                raw_command = input_stream.readline()
            except KeyboardInterrupt:
                print(
                    "\nInterrupted. No real systems were changed.",
                    file=output_stream,
                )
                return 130
            if raw_command == "":
                print("\nInput ended. Leaving the simulator safely.", file=output_stream)
                return 0
            result = processor.execute(raw_command)
            if result.message:
                print(result.message, file=output_stream)
            if result.should_quit:
                print(
                    f"\nSession summary: {scoreboard.incidents_resolved} incident(s) resolved, "
                    f"{scoreboard.points} total points, "
                    f"{scoreboard.precision:.0%} block precision.",
                    file=output_stream,
                )
                return 0

        print(
            f"Progress: {scoreboard.incidents_resolved}/{args.rounds} incidents resolved | "
            f"Total points: {scoreboard.points} | Precision: {scoreboard.precision:.0%}",
            file=output_stream,
        )

    print(
        f"\nTraining complete. {scoreboard.incidents_resolved} incidents resolved; "
        f"final score {scoreboard.points}; block precision {scoreboard.precision:.0%}.",
        file=output_stream,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
