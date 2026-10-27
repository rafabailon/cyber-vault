# Cyber Vault: Incident Response Simulator

Cyber Vault is a defensive, terminal-based training exercise. Review synthetic security events, investigate explainable detection findings, contain suspicious addresses using a virtual firewall, restore simulated system integrity, and close incidents for points.

## Safety and scope

- The application never opens sockets, sends packets, scans hosts, or modifies operating-system firewall settings.
- Every event and response action is simulated in memory.
- Generated addresses come only from the IPv4 documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`.
- Simulated web events contain inert training markers, not executable payloads.

This is a learning game, not a real monitoring or incident-response tool.

## Requirements

- Python 3.10 or later
- No third-party runtime dependencies

## Run

From the project root:

```sh
PYTHONPATH=src python3 src/cyber_vault.py
```

Or use the Makefile shortcut:

```sh
make run
```

The default session has three incidents with the `CV-` identifier prefix. Difficulty and log volume increase from one incident to the next. Use a seed to reproduce the same set of scenarios:

```sh
PYTHONPATH=src python3 src/cyber_vault.py --seed 42 --rounds 4 --difficulty 2
```

Options:

- `--seed INTEGER`: repeatable procedural generation
- `--rounds INTEGER`: 1 to 10 incidents (default: 3)
- `--difficulty INTEGER`: starting difficulty from 1 to 10 (default: 1)
- `--version`: show the application name and version
- `--help`: show command-line usage

Install a local command if desired:

```sh
python3 -m pip install -e .
cyber-vault --seed 42 --rounds 3
```

## Analyst commands

```text
help
logs
logs type=login_failure
logs ip=192.0.2.10 severity=MEDIUM
analyze
status
block 192.0.2.10
unblock 192.0.2.10
restore
close
quit
```

The generator displays only synthetic records. `analyze` reports threshold-based rules and evidence, but does not reveal the scenario answer key. Blocking a benign address incurs a penalty; that penalty can be reversed by removing the virtual rule. For compromised scenarios, contain every malicious source before running the simulated integrity-restoration step. A clean integrity check is also required to close clean scenarios.

## Scoring and progression

Correct containment, restoration, and incident closure add points. False-positive blocks deduct points. A small time bonus rewards efficient analysis. Each incident raises the difficulty and synthetic log volume up to the selected difficulty cap.

## Tests

Run the unit and integration suite:

```sh
make test
```

The suite currently runs **33 tests**, all passing. The standard-library test suite covers model validation, seeded generation, documentation-only addresses, all detector rules and thresholds, firewall state, filtering, false-positive penalties, restoration gates, scoring, command parsing, CLI argument bounds and version output, and complete seeded terminal scenarios.

Measure executed source-line coverage without external packages:

```sh
make coverage
```

The suite executes 100% of the Python source lines in `src/` using Python's standard-library `trace` module. This is line execution coverage, not branch coverage. The generated report is written to the ignored `coverage-report/` directory.

Remove bytecode, coverage output, and build artifacts:

```sh
make clean
```

## Structure

```text
src/
  branding.py    Application name, version, incident prefix, and prompt
  models.py      Typed events, findings, scenarios, and address validation
  generator.py   Seedable synthetic event generation
  detector.py    Explainable threshold-based analysis
  firewall.py    In-memory virtual firewall
  session.py     Incident objectives, response state, and scoring
  commands.py    Safe command parsing and output
  cyber_vault.py Terminal loop and command-line options
tests/
  test_models.py
  test_generator.py
  test_detector.py
  test_firewall.py
  test_session.py
  test_commands.py
  test_cli.py
```
