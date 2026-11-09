import shlex
import unittest
from unittest.mock import patch

import server
from core import store


class ResourceLimitTests(unittest.TestCase):
    def setUp(self):
        self.ch = store.Challenge(
            id="r1", name="one", category="pwn", workdir="/tmp/one", root="/tmp")
        self.unit = {"tmux": {"ubz_id": "0123456789abcdef0123456789abcdef"}}

    def test_scope_wraps_without_changing_harness_command(self):
        original = "DSH_PERMISSION_MODE=danger-full-access dsh-tui --resume abc"
        with patch.object(server, "_resource_limits_supported", True), \
             patch.dict(server.CONFIG, {"resource_limits": {
                 "enabled": True, "scope_enabled": True,
                 "slice_name": "ubz-ctf.slice",
                 "slice_cpu_quota": 900, "slice_memory_high": "12G",
             }}):
            wrapped = server._resource_limited_command(self.ch, self.unit, original)
        self.assertIn("--slice ubz-ctf.slice", wrapped)
        self.assertNotIn("CPUQuota=", wrapped)
        self.assertNotIn("MemoryHigh=", wrapped)
        self.assertIn("ubz-0123456789abcdef", wrapped)
        self.assertEqual(shlex.split(wrapped)[-1], original)

        self.ch.category = "web"
        with patch.object(server, "_resource_limits_supported", True), \
             patch.dict(server.CONFIG, {"resource_limits": {
                 "enabled": True, "scope_enabled": True}}):
            light = server._resource_limited_command(self.ch, self.unit, original)
        self.assertIn("--slice ubz-ctf.slice", light)

    def test_unsupported_scope_leaves_command_untouched(self):
        original = "claude -c --dangerously-skip-permissions"
        with patch.object(server, "_resource_limits_supported", False):
            self.assertEqual(
                server._resource_limited_command(self.ch, self.unit, original), original)

    def test_scope_disabled_does_not_limit_running_commands(self):
        original = "claude -c --dangerously-skip-permissions"
        with patch.object(server, "_resource_limits_supported", True), \
             patch.dict(server.CONFIG, {"resource_limits": {
                 "enabled": True, "scope_enabled": False}}):
            self.assertEqual(
                server._resource_limited_command(self.ch, self.unit, original), original)

    def test_admission_rejects_low_memory_and_high_load(self):
        low_mem = "MemAvailable: 1024000 kB\n"
        enough_mem = "MemAvailable: 8192000 kB\n"
        with patch.object(server.Path, "read_text", side_effect=[low_mem, "1.0 0.5 0.2\n"]):
            allowed, reason = server._admission_status()
        self.assertFalse(allowed)
        self.assertIn("可用内存", reason)

        with patch.object(server.Path, "read_text", side_effect=[enough_mem, "99.0 0.5 0.2\n"]):
            allowed, reason = server._admission_status()
        self.assertFalse(allowed)
        self.assertIn("每核负载", reason)

        with patch.object(server.Path, "read_text", side_effect=[enough_mem, "0.5 0.2 0.1\n"]):
            allowed, reason = server._admission_status()
        self.assertTrue(allowed)
        self.assertEqual(reason, "")

    def test_memory_ratio_uses_current_physical_ram(self):
        meminfo = "MemTotal:       24556872 kB\nMemAvailable:  20996784 kB\n"
        with patch.object(server.Path, "read_text", return_value=meminfo), \
             patch.dict(server.CONFIG, {"resource_limits": {
                 "slice_memory_ratio": 0.8, "slice_memory_high": ""}}):
            value = server._slice_memory_high()
            display = server._slice_memory_display()
        self.assertEqual(value, str(int(24556872 * 0.8 * 1024)))
        self.assertTrue(display.endswith("G"))

    def test_health_exposes_resource_gate(self):
        health = server.get_health()
        self.assertIn("scope_enabled", health["resource_limits"])
        self.assertIn("admission_control", health["resource_limits"])
        self.assertIn("gate_reason", health["resource_limits"])


if __name__ == "__main__":
    unittest.main()
