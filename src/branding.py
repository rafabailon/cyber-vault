"""Shared product identity for Cyber Vault."""

from __future__ import annotations

APP_NAME = "Cyber Vault"
APP_SLUG = "cyber-vault"
APP_DESCRIPTION = (
    "A defensive, isolated incident-response training simulator for the terminal."
)
VERSION = "1.1.0"
INCIDENT_PREFIX = "CV"
PROMPT = f"{APP_SLUG}> "
BANNER = (
    "CYBER VAULT // INCIDENT RESPONSE SIMULATOR\n"
    "Training environment only. All logs and firewall rules are synthetic and local.\n"
    "Type 'help' for commands. No real systems or networks are accessed."
)
