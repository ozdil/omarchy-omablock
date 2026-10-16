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
    def setUp(self):
        # Never let a test touch the real /etc/hosts, browser policy dirs, resolvectl or nft,
        # even when the suite runs as root (CI containers, sudo).
        self._sandbox = tempfile.TemporaryDirectory()
        sandbox = self._sandbox.name
        self._saved = {
            name: getattr(omablock_sync, name)
            for name in (
                "HOSTS_PATH", "BACKUP_PATH", "TEMP_PATH", "POLICY_DIRS", "KERNEL_STATE_DIR", "PRE_RESTORE_PATH",
                "flush_dns_cache", "apply_nftables_rules", "clear_nftables_rules",
            )
        }
        omablock_sync.HOSTS_PATH = os.path.join(sandbox, "hosts")
        omablock_sync.BACKUP_PATH = os.path.join(sandbox, "hosts.omablock.bak")
        omablock_sync.TEMP_PATH = os.path.join(sandbox, "hosts.omablock.tmp")
        omablock_sync.POLICY_DIRS = [os.path.join(sandbox, "policies")]
        omablock_sync.KERNEL_STATE_DIR = os.path.join(sandbox, "run-omablock")
        omablock_sync.PRE_RESTORE_PATH = os.path.join(sandbox, "hosts.omablock.pre-restore")
        omablock_sync.flush_dns_cache = lambda: None
        omablock_sync.apply_nftables_rules = lambda: None
        omablock_sync.clear_nftables_rules = lambda: None

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(omablock_sync, name, value)
        self._sandbox.cleanup()

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
            policy_file = os.path.join(tmpdir, "omablock_policies.json")
            
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
                f.write('{"_omablock_managed": true, "DnsOverHttpsMode": "off", "QuicAllowed": false}\n')
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

    def test_apply_rules_aborts_on_unreadable_or_symlink_hosts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rules_file = os.path.join(tmpdir, "rules.txt")
            with open(rules_file, "w") as f:
                f.write("0.0.0.0 badtracker.com\n")

            mock_hosts = os.path.join(tmpdir, "hosts")
            mock_backup = os.path.join(tmpdir, "hosts.bak")
            mock_temp = os.path.join(tmpdir, "hosts.tmp")

            omablock_sync.HOSTS_PATH = mock_hosts
            omablock_sync.BACKUP_PATH = mock_backup
            omablock_sync.TEMP_PATH = mock_temp

            # Case 1: mock_hosts is a symlink
            real_hosts = os.path.join(tmpdir, "real_hosts")
            with open(real_hosts, "w") as f:
                f.write("127.0.0.1 localhost\n")
            os.symlink(real_hosts, mock_hosts)

            with self.assertRaises(SystemExit):
                omablock_sync.apply_rules(rules_file)

            os.unlink(mock_hosts)

            # Case 2: mock_hosts exists as unreadable / error on open.
            # root ignores mode 000, so this case only means something for normal users.
            if os.geteuid() == 0:
                return
            with open(mock_hosts, "w") as f:
                f.write("127.0.0.1 localhost\n")
            os.chmod(mock_hosts, 0o000)

            # In user space test, opening 000 file causes PermissionError -> SystemExit
            try:
                with self.assertRaises(SystemExit):
                    omablock_sync.apply_rules(rules_file)
            finally:
                os.chmod(mock_hosts, 0o644)

    def test_clear_rules_aborts_on_symlink_hosts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_hosts = os.path.join(tmpdir, "hosts")
            real_hosts = os.path.join(tmpdir, "real_hosts")
            with open(real_hosts, "w") as f:
                f.write("127.0.0.1 localhost\n")
            os.symlink(real_hosts, mock_hosts)

            omablock_sync.HOSTS_PATH = mock_hosts
            with self.assertRaises(SystemExit):
                omablock_sync.clear_rules()

    def test_read_hosts_file_size_limit_exceeded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_hosts = os.path.join(tmpdir, "hosts")
            with open(mock_hosts, "w") as f:
                f.write("127.0.0.1 localhost\n")

            saved_limit = omablock_sync.MAX_HOSTS_SIZE
            try:
                omablock_sync.MAX_HOSTS_SIZE = 5  # smaller than file content
                with self.assertRaises(SystemExit):
                    omablock_sync.read_hosts_file(mock_hosts)
            finally:
                omablock_sync.MAX_HOSTS_SIZE = saved_limit

    def test_read_hosts_file_truncation_detection(self):
        from unittest.mock import patch, MagicMock

        with tempfile.TemporaryDirectory() as tmpdir:
            mock_hosts = os.path.join(tmpdir, "hosts")
            with open(mock_hosts, "w") as f:
                f.write("127.0.0.1 localhost\n")

            mock_stat = MagicMock()
            mock_stat.st_mode = 0o100644  # regular file
            mock_stat.st_size = 10  # within MAX_HOSTS_SIZE

            # Simulate f.read(MAX_HOSTS_SIZE) returning 10 chars, then f.read(1) returning leftover char
            mock_file = MagicMock()
            mock_file.read.side_effect = ["1234567890", "X"]

            with patch("os.fstat", return_value=mock_stat), \
                 patch("builtins.open", return_value=mock_file):
                with self.assertRaises(SystemExit):
                    omablock_sync.read_hosts_file(mock_hosts)

    def test_read_hosts_file_non_regular_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # directory instead of regular file
            sub_dir = os.path.join(tmpdir, "sub_dir")
            os.mkdir(sub_dir)
            with self.assertRaises(SystemExit):
                omablock_sync.read_hosts_file(sub_dir)


    def test_strip_keeps_user_entries_after_unterminated_block(self):
        original = (
            "127.0.0.1 localhost\n"
            "# --- BEGIN OMABLOCK MANAGED RULES ---\n"
            "# Managed automatically by OmaBlock (ozdil.omablock). Do not edit inside this block.\n"
            "0.0.0.0 evil.com\n"
            "10.0.0.5 nas.home\n"
        )
        cleaned = omablock_sync.strip_omablock_block(original)
        self.assertIn("10.0.0.5 nas.home", cleaned)
        self.assertNotIn("evil.com", cleaned)
        self.assertNotIn("OMABLOCK MANAGED RULES", cleaned)

    def test_apply_preserves_non_utf8_bytes(self):
        with open(omablock_sync.HOSTS_PATH, "wb") as f:
            f.write(b"127.0.0.1 localhost # caf\xe9\n")
        rules_file = os.path.join(self._sandbox.name, "rules.txt")
        with open(rules_file, "w") as f:
            f.write("0.0.0.0 badtracker.com\n")
        omablock_sync.apply_rules(rules_file)
        with open(omablock_sync.HOSTS_PATH, "rb") as f:
            data = f.read()
        self.assertIn(b"caf\xe9", data)
        self.assertIn(b"0.0.0.0 badtracker.com", data)

    def test_clear_removes_policy_even_without_hosts_block(self):
        pdir = omablock_sync.POLICY_DIRS[0]
        omablock_sync.apply_browser_doh_policy()
        target = os.path.join(pdir, omablock_sync.POLICY_FILENAME)
        self.assertTrue(os.path.exists(target))
        with open(omablock_sync.HOSTS_PATH, "w") as f:
            f.write("127.0.0.1 localhost\n")
        omablock_sync.clear_rules()
        self.assertFalse(os.path.exists(target))

    def test_nft_script_replaces_table(self):
        import inspect
        src = inspect.getsource(self._saved["apply_nftables_rules"])
        self.assertIn("delete table inet omablock", src)

    def test_kernel_state_file_written_for_unprivileged_engine(self):
        import json
        from unittest.mock import patch
        with patch.object(omablock_sync.shutil, "which", return_value=None):
            omablock_sync.write_kernel_state()
        path = os.path.join(omablock_sync.KERNEL_STATE_DIR, omablock_sync.KERNEL_STATE_FILE)
        with open(path) as f:
            state = json.load(f)
        self.assertEqual(state, {"nft_available": False, "kernel_active": False,
                                 "kernel_rule_count": 0, "blackout_active": False})
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)

    def test_blackout_script_exempts_loopback_by_output_interface(self):
        self.assertIn('oifname != "lo"', omablock_sync.BLACKOUT_SCRIPT)
        self.assertNotIn("iifname", omablock_sync.BLACKOUT_SCRIPT)
        self.assertIn("delete table inet omablock_blackout", omablock_sync.BLACKOUT_SCRIPT)

    def test_apply_keeps_hosts_mode(self):
        with open(omablock_sync.HOSTS_PATH, "w") as f:
            f.write("127.0.0.1 localhost\n")
        os.chmod(omablock_sync.HOSTS_PATH, 0o640)
        rules_file = os.path.join(self._sandbox.name, "rules.txt")
        with open(rules_file, "w") as f:
            f.write("0.0.0.0 badtracker.com\n")
        omablock_sync.apply_rules(rules_file)
        self.assertEqual(os.stat(omablock_sync.HOSTS_PATH).st_mode & 0o777, 0o640)
        omablock_sync.clear_rules()
        self.assertEqual(os.stat(omablock_sync.HOSTS_PATH).st_mode & 0o777, 0o640)

    def test_helper_lock_is_exclusive(self):
        import fcntl
        fd = omablock_sync.acquire_helper_lock()
        try:
            other = os.open(os.path.join(omablock_sync.KERNEL_STATE_DIR, "helper.lock"), os.O_RDWR)
            with self.assertRaises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.close(other)
        finally:
            os.close(fd)

    def test_restore_backup(self):
        with open(omablock_sync.HOSTS_PATH, "w") as f:
            f.write("127.0.0.1 localhost\n10.0.0.5 nas.home\n")
        rules_file = os.path.join(self._sandbox.name, "rules.txt")
        with open(rules_file, "w") as f:
            f.write("0.0.0.0 badtracker.com\n")
        omablock_sync.apply_rules(rules_file)  # creates the backup
        with open(omablock_sync.HOSTS_PATH, "a") as f:
            f.write("192.168.1.9 added-later\n")
        omablock_sync.restore_backup()
        with open(omablock_sync.HOSTS_PATH) as f:
            restored = f.read()
        self.assertIn("nas.home", restored)
        self.assertNotIn("badtracker.com", restored)
        self.assertNotIn("added-later", restored)
        with open(omablock_sync.PRE_RESTORE_PATH) as f:
            self.assertIn("added-later", f.read())


if __name__ == "__main__":
    unittest.main()
