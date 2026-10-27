"""In-memory firewall rules; intentionally has no networking capability."""

from __future__ import annotations

import ipaddress

from models import IPAddress, parse_ipv4


def _coerce_address(address: str | IPAddress) -> IPAddress:
    """Accept a validated address object or parse a strict IPv4 string."""
    if isinstance(address, ipaddress.IPv4Address):
        return address
    return parse_ipv4(address)


class VirtualFirewall:
    """Maintain an isolated set of blocked IPv4 addresses."""

    def __init__(self) -> None:
        self._blocked: set[IPAddress] = set()

    @property
    def blocked(self) -> frozenset[IPAddress]:
        return frozenset(self._blocked)

    def block(self, address: str | IPAddress) -> bool:
        """Add an address to the virtual deny-list; return whether it was new."""
        parsed = _coerce_address(address)
        was_new = parsed not in self._blocked
        self._blocked.add(parsed)
        return was_new

    def unblock(self, address: str | IPAddress) -> bool:
        """Remove a rule if present and report whether the set changed."""
        parsed = _coerce_address(address)
        if parsed not in self._blocked:
            return False
        self._blocked.remove(parsed)
        return True

    def is_blocked(self, address: str | IPAddress) -> bool:
        parsed = _coerce_address(address)
        return parsed in self._blocked
