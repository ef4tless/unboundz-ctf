import tempfile
import unittest
from unittest.mock import patch

import server
from core import store


class SetFlagStatusTests(unittest.TestCase):
    def make_challenge(self, *, status="running", pane="%1"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        ch = store.Challenge(
            id="abc123",
            name="test",
            category="misc",
            workdir=tmp.name,
            root=tmp.name,
            tmux={"session": "test", "pane": pane} if pane else {"session": "test"},
            status=status,
        )
        ch.save()
        return ch

    def set_flag(self, ch, value):
        with patch.object(server, "_get", return_value=ch):
            return server.set_flag(ch.id, server.FlagIn(flag=value))

    def test_non_empty_flag_marks_challenge_solved(self):
        ch = self.make_challenge(status="running")

        result = self.set_flag(ch, "  flag{ok}  ")

        self.assertEqual(result["flag"], "flag{ok}")
        self.assertEqual(result["status"], "solved")

    def test_clearing_flag_restores_running_for_active_harness(self):
        ch = self.make_challenge(status="solved")
        ch.flag = "flag{old}"
        with (
            patch.object(server.tmuxctl, "pane_exists", return_value=True),
            patch.object(server.tmuxctl, "pane_current_command", return_value="codex"),
        ):
            result = self.set_flag(ch, "  ")

        self.assertEqual(result["flag"], "")
        self.assertEqual(result["status"], "running")

    def test_clearing_flag_detects_exited_harness(self):
        ch = self.make_challenge(status="solved")
        ch.flag = "flag{old}"
        with (
            patch.object(server.tmuxctl, "pane_exists", return_value=True),
            patch.object(server.tmuxctl, "pane_current_command", return_value="zsh"),
        ):
            result = self.set_flag(ch, "")

        self.assertEqual(result["status"], "exited")

    def test_clearing_flag_without_a_pane_returns_to_ready(self):
        ch = self.make_challenge(status="solved", pane="")
        ch.flag = "flag{old}"

        result = self.set_flag(ch, "")

        self.assertEqual(result["status"], "ready")

    def test_clearing_flag_detects_missing_pane(self):
        ch = self.make_challenge(status="solved")
        ch.flag = "flag{old}"
        with patch.object(server.tmuxctl, "pane_exists", return_value=False):
            result = self.set_flag(ch, "")

        self.assertEqual(result["status"], "pane_gone")


if __name__ == "__main__":
    unittest.main()
