"""Regression contract for the pre-build Chrony time-synchronization gate."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "ansible" / "site.yml"
DEFAULTS = ROOT / "ansible" / "group_vars" / "all.yml"
TIME_SYNC = ROOT / "ansible" / "roles" / "time_sync" / "tasks" / "main.yml"


class TimeSyncContractTests(unittest.TestCase):
    def test_time_sync_proves_a_fresh_selected_source_before_mutation(self) -> None:
        source = TIME_SYNC.read_text(encoding="utf-8")
        require_client = source.index(
            "- name: Require preinstalled Chrony client before time-dependent mutation"
        )
        enable = source.index("- name: Enable the configured Chrony time source")
        socket = source.index("- name: Require Chrony's local command socket")
        baseline = source.index("- name: Capture Chrony accepted-sample baseline")
        arm = source.index("- name: Arm one Chrony correction for the next accepted sample")
        burst = source.index("- name: Request fresh Chrony samples before package or image operations")
        fresh_sample = source.index(
            "- name: Require a fresh accepted sample from Chrony's selected source"
        )
        waitsync = source.index("- name: Wait for a bounded Chrony synchronization result")
        verify = source.index(
            "- name: Require Chrony to report a bounded externally synchronized wall clock"
        )
        self.assertLess(require_client, enable)
        self.assertLess(enable, socket)
        self.assertLess(socket, baseline)
        self.assertLess(baseline, arm)
        self.assertLess(arm, burst)
        self.assertLess(burst, fresh_sample)
        self.assertLess(fresh_sample, waitsync)
        self.assertLess(waitsync, verify)
        for required in (
            "/var/run/chrony/chronyd.sock",
            "Total good RX",
            "- makestep",
            '"0.1"',
            "- burst",
            "- 4/4",
            '"-n", "sources"',
            "selected Chrony source has not accepted a fresh NTP sample",
            "final selected Chrony source has not accepted a fresh NTP sample",
            '"{{ chrony_rx_baseline.stdout }}"',
            "until: chrony_fresh_sample.rc == 0",
            "- waitsync",
            "aigw_time_sync_max_offset_seconds",
        ):
            self.assertIn(required, source)
        self.assertNotIn("ansible.builtin.pause", source)
        self.assertNotIn("ansible.builtin.dnf", source)

    def test_time_sync_rejects_local_mode_and_bounds_estimated_error(self) -> None:
        source = TIME_SYNC.read_text(encoding="utf-8")
        for required in (
            "7F7F0101",
            "Root delay",
            "Root dispersion",
            "estimated_error = system_time + root_dispersion + (0.5 * root_delay)",
            "Chrony estimated error",
            "Leap status",
            "Reference ID",
        ):
            self.assertIn(required, source)

    def test_clock_policy_is_enabled_by_default_and_checked_before_mutation(self) -> None:
        defaults = DEFAULTS.read_text(encoding="utf-8")
        site = SITE.read_text(encoding="utf-8")
        self.assertIn("aigw_require_time_sync: true", defaults)
        self.assertIn("aigw_time_sync_max_offset_seconds: 5", defaults)
        self.assertIn("aigw_require_time_sync is boolean", site)
        self.assertIn("aigw_time_sync_max_offset_seconds | int >= 1", site)
        self.assertIn("aigw_time_sync_max_offset_seconds | int <= 300", site)
        firewall_preflight = site.index("- role: firewall_preflight")
        time_sync = site.index("- role: time_sync")
        selinux = site.index("- role: selinux_baseline")
        os_baseline = site.index("- role: os_baseline")
        docker_networks = site.index("- role: docker_networks")
        self.assertLess(firewall_preflight, time_sync)
        self.assertLess(time_sync, selinux)
        self.assertLess(time_sync, os_baseline)
        self.assertLess(time_sync, docker_networks)

    def test_customer_chrony_sources_are_not_overwritten(self) -> None:
        source = TIME_SYNC.read_text(encoding="utf-8")
        self.assertNotIn("/etc/chrony.conf", source)
        self.assertNotIn("chrony.conf.j2", source)


if __name__ == "__main__":
    unittest.main()
