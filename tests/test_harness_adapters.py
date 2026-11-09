"""pi / zcode harness 的真实 TUI 特征回归测试 (pi 1.5.0, zcode 0.17.1)。"""

import unittest
from unittest.mock import call, patch

from core import harness, monitor, store, tmuxctl


class PiZCodeHarnessTests(unittest.TestCase):
    def test_launch_and_resume_commands(self):
        for cfg in (store.DEFAULT_CONFIG, store.load_config()):
            with self.subTest(config=type(cfg).__name__):
                self.assertEqual(harness.launch_command(cfg, "pi"), "pi --approve")
                self.assertEqual(harness.resume_command(cfg, "pi"),
                                 "pi --continue --approve")
                self.assertEqual(harness.launch_command(cfg, "zcode"),
                                 "zcode --mode yolo")
                self.assertEqual(harness.resume_command(cfg, "zcode"),
                                 "zcode --continue --mode yolo")
                self.assertIn("pi", harness.BOOT_PROMPT_WAIT)
                self.assertIn("zcode", harness.BOOT_PROMPT_WAIT)

    def test_pi_working_border_is_busy_but_plain_text_is_not(self):
        busy_lines = [
            "── ⠦ Working ─────────────────────────────────────",
            " ⠋ Working (escape to interrupt)",
            "── ⠙ Retrying (1/3) in 2s... ──────────────────────",
            " ⠹ Compacting context... (escape to cancel)",
        ]
        for line in busy_lines:
            with self.subTest(line=line):
                self.assertTrue(tmuxctl.is_busy([line]))

        for line in ("Working on the exploit", "── Working ─────",
                     "✻ Worked for 12s"):
            with self.subTest(line=line):
                self.assertFalse(tmuxctl.is_busy([line]))

    def test_pi_idle_footer_requires_not_busy(self):
        idle = [
            "────────────────────────────────────────────────────",
            "/tmp/ubz-pi-probe",
            "↑5.5k ↓57 R13k CH93.0% $0.011 0.4%/1.0M (auto)  ctyun/glm • high",
        ]
        self.assertTrue(harness._has_idle_prompt(idle))
        self.assertTrue(monitor.Monitor._looks_idle_at_prompt("\n".join(idle)))

        busy = [*idle[:-2], "── ⠦ Working ─────────────────────", *idle[-2:]]
        self.assertTrue(tmuxctl.is_busy(busy))
        self.assertFalse(harness._has_idle_prompt(busy))
        self.assertFalse(monitor.Monitor._looks_idle_at_prompt("\n".join(busy)))

    def test_zcode_idle_placeholder_english_and_chinese(self):
        for placeholder in ("Type a prompt", "输入提示词"):
            lines = [
                "╭─ Yolo ─────────────────────────────────────────╮",
                f"│ {placeholder}                                         │",
                "│ ctyun/glm magpie | max                            │",
                "╰──────────────────────────────────────────────────╯",
            ]
            with self.subTest(placeholder=placeholder):
                self.assertTrue(harness._has_idle_prompt(lines))
                self.assertTrue(monitor.Monitor._looks_idle_at_prompt("\n".join(lines)))

        for placeholder in ("Type to queue input", "输入内容会排队"):
            lines = [f"│ {placeholder}", " ⠦ esc to interrupt"]
            with self.subTest(placeholder=placeholder):
                self.assertTrue(tmuxctl.is_busy(lines))
                self.assertFalse(harness._has_idle_prompt(lines))
                self.assertFalse(monitor.Monitor._looks_idle_at_prompt("\n".join(lines)))

        # 恢复时输入框可能先于模型/MCP 就绪出现, 此时还不能注入。
        self.assertFalse(harness._has_idle_prompt([
            "│ Type a prompt",
            "│ - - | -",
        ]))

    def test_pi_ctrl_c_double_tap_is_faster_than_500ms(self):
        with (patch.object(tmuxctl, "pane_exists", return_value=True),
              patch.object(tmuxctl, "pane_current_command", return_value="pi"),
              patch.object(tmuxctl, "_run") as run,
              patch.object(tmuxctl.time, "sleep") as sleep):
            tmuxctl.interrupt_pane("%pi", times=3, harness_name="pi")

        self.assertEqual(run.call_args_list, [
            call(["send-keys", "-t", "%pi", "C-c"], check=False),
            call(["send-keys", "-t", "%pi", "C-c"], check=False),
        ])
        self.assertEqual(sleep.call_args_list, [call(0.2), call(0.2)])


if __name__ == "__main__":
    unittest.main()
