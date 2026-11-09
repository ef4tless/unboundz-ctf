import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import server
from core import store


class BoardToolingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.ch = store.create_challenge(
            self.root, name="tooling", category="misc", harnesses=["dsh"])
        self.unit = self.ch.attempts[0]
        self.tool = store.PROJECT_DIR / "bin" / "ubz-board"

    def test_agents_tooling_is_idempotent_and_preserves_custom_text(self):
        agents = Path(self.ch.workdir) / "AGENTS.md"
        agents.write_text(agents.read_text() + "\n人工补充：保留这条自定义纪律。\n")
        store.ensure_collab_files(self.ch)
        first = agents.read_text()
        store.ensure_collab_files(self.ch)
        second = agents.read_text()

        self.assertEqual(first, second)
        self.assertIn("人工补充：保留这条自定义纪律。", second)
        self.assertEqual(second.count(store._TOOLING_START), 1)
        self.assertIn(str(self.tool), second)
        self.assertIn("UBZ_BOARD_FILE", second)
        self.assertIn("Skills", second)
        self.assertIn("多路复核", second)

    def test_flags_are_deduplicated_by_value_and_source(self):
        board = Path(self.ch.workdir) / "board.md"
        text = "flag{same}（逐字见于远程响应）"
        self.assertTrue(store.append_board_entry(board, "flag", text, source="dsh"))
        self.assertTrue(store.append_board_entry(board, "flag", text, source="claude"))
        self.assertFalse(store.append_board_entry(board, "flag", text, source="claude"))
        content = board.read_text()
        self.assertEqual(content.count("flag{same}"), 2)
        self.assertIn("来源：dsh", content)
        self.assertIn("来源：claude", content)

    def test_tool_uses_explicit_board_file_from_unrelated_cwd(self):
        elsewhere = Path(self.root) / "elsewhere"
        elsewhere.mkdir()
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "UBZ_BOARD_FILE": str(Path(self.ch.workdir) / "board.md"),
            "UBZ_HARNESS": "dsh",
        }
        result = subprocess.run(
            [str(self.tool), "fact", "Skills 子进程也能写对黑板"],
            cwd=elsewhere, env=env, capture_output=True, text=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        board = (Path(self.ch.workdir) / "board.md").read_text()
        self.assertIn("Skills 子进程也能写对黑板", board)
        self.assertFalse((elsewhere / "board.md").exists())

    def test_launch_environment_exposes_short_and_absolute_commands(self):
        uid = self.unit["tmux"]["ubz_id"]
        command = server._unit_env_command(self.ch, self.unit, uid)
        result = subprocess.run(
            ["bash", "-c",
             command + ' && command -v ubz-board && "$UBZ_BOARD_BIN" show'],
            cwd=self.unit["workdir"],
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            capture_output=True, text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(self.tool), result.stdout)
        self.assertIn("board.md", result.stdout)


if __name__ == "__main__":
    unittest.main()
