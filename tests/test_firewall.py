import unittest

from firewall import VirtualFirewall


class VirtualFirewallTests(unittest.TestCase):
    def test_block_unblock_and_membership(self):
        firewall = VirtualFirewall()
        self.assertTrue(firewall.block("192.0.2.9"))
        self.assertFalse(firewall.block("192.0.2.9"))
        self.assertTrue(firewall.is_blocked("192.0.2.9"))
        self.assertEqual(len(firewall.blocked), 1)
        self.assertTrue(firewall.unblock("192.0.2.9"))
        self.assertFalse(firewall.unblock("192.0.2.9"))
        self.assertFalse(firewall.is_blocked("192.0.2.9"))

    def test_invalid_address_is_rejected(self):
        firewall = VirtualFirewall()
        with self.assertRaisesRegex(ValueError, "Invalid IPv4"):
            firewall.block("300.1.1.1")
        with self.assertRaisesRegex(ValueError, "Only IPv4"):
            firewall.is_blocked("2001:db8::1")

    def test_blocked_snapshot_cannot_mutate_firewall(self):
        firewall = VirtualFirewall()
        firewall.block("203.0.113.2")
        with self.assertRaises(AttributeError):
            firewall.blocked.add("203.0.113.3")


if __name__ == "__main__":
    unittest.main()
