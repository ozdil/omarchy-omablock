#!/usr/bin/env python3
"""
Offline Simulation and Verification Test for omablock-hosts-sync
Tests domain filtering, injection defense, and DoH policies in an isolated sandbox.
"""

import os
import sys
import tempfile
import unittest

# Import the helper module directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import importlib.machinery
import importlib.util

loader = importlib.machinery.SourceFileLoader("omablock_sync", os.path.abspath(os.path.join(os.path.dirname(__file__), "../omablock-hosts-sync")))
spec = importlib.util.spec_from_loader(loader.name, loader)
omablock_sync = importlib.util.module_from_spec(spec)
loader.exec_module(omablock_sync)


class TestOmaBlockSyncHelper(unittest.TestCase):
    def test_domain_regex_validation(self):
        valid = [
            "google.com",
            "adservice.google.com",
            "tracker-1.example.org",
            "sub.domain.co.uk",
            "1dot1dot1dot1.cloudflare-dns.com",
        ]
        for d in valid:
            self.assertIsNotNone(omablock_sync.DOMAIN_REGEX.match(d), f"Domain '{d}' should be valid")

        invalid = [
            "evil.com\n0.0.0.0 bank.com",
            "evil.com; rm -rf /",
            "evil.com`id`",
            "evil.com$(reboot)",
            "evil..com",
            "-start-hyphen.com",
            "evil.com/path",
            "evil.com:80",
            "*.evil.com",
            "",
        ]
        for d in invalid:
            self.assertIsNone(omablock_sync.DOMAIN_REGEX.match(d), f"Invalid payload '{d}' must be rejected")

    def test_strip_omablock_block(self):
        original = (
            "127.0.0.1 localhost\n"
            "::1 localhost\n"
            "# --- BEGIN OMABLOCK MANAGED RULES ---\n"
            "# Managed automatically\n"
            "0.0.0.0 evil.com\n"
            "# --- END OMABLOCK MANAGED RULES ---\n"
            "192.168.1.50 myserver.local\n"
        )
        cleaned = omablock_sync.strip_omablock_block(original)
        self.assertIn("127.0.0.1 localhost", cleaned)
        self.assertIn("192.168.1.50 myserver.local", cleaned)
        self.assertNotIn("evil.com", cleaned)
        self.assertNotIn("OMABLOCK MANAGED RULES", cleaned)

    def test_browser_doh_policy_preservation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = os.path.join(tmpdir, "omablock_doh.json")
            
            # 1. Unmanaged foreign policy
            with open(policy_file, "w") as f:
                f.write('{"EnterprisePolicy": "CustomVal"}\n')
            
            # Helper should NOT overwrite foreign policy
            omablock_sync.POLICY_DIRS = [tmpdir]
            omablock_sync.apply_browser_doh_policy()
            with open(policy_file, "r") as f:
                content = f.read()
            self.assertIn("CustomVal", content)
            self.assertNotIn('"DnsOverHttpsMode": "off"', content)

            # 2. Managed policy can be removed safely
            with open(policy_file, "w") as f:
                f.write('{"_omablock_managed": true, "DnsOverHttpsMode": "off"}\n')
            omablock_sync.clear_browser_doh_policy()
            self.assertFalse(os.path.exists(policy_file))

    def test_symlink_rejection_in_apply(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = os.path.join(tmpdir, "real_rules.txt")
            with open(target, "w") as f:
                f.write("0.0.0.0 badsite.com\n")
            symlink = os.path.join(tmpdir, "symlink_rules.txt")
            os.symlink(target, symlink)

            # Applying from a symlink must exit with error
            with self.assertRaises(SystemExit):
                omablock_sync.apply_rules(symlink)

    def test_oversized_rules_rejection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            oversized = os.path.join(tmpdir, "huge_rules.txt")
            with open(oversized, "wb") as f:
                f.seek(51 * 1024 * 1024)
                f.write(b"\0")

            # Applying rules file exceeding 50 MB limit must exit with error
            with self.assertRaises(SystemExit):
                omablock_sync.apply_rules(oversized)


if __name__ == "__main__":
    unittest.main()
