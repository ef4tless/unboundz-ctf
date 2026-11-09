import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server
from core import monitor, store, tmuxctl


class PaneIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def make_challenge(self, name="one", harness="claude"):
        return store.create_challenge(
            self.root, name=name, category="pwn", harnesses=[harness])

    def test_new_attempts_have_distinct_persistent_ids(self):
        ch = store.create_challenge(self.root, name="multi", category="misc",
                                    harnesses=["claude", "dsh"])
        ids = [a["tmux"]["ubz_id"] for a in ch.attempts]
        self.assertEqual(len(set(ids)), 2)
        self.assertTrue(all(len(uid) == 32 for uid in ids))
        loaded = store.Challenge.load(ch.meta_path)
        self.assertEqual([a["tmux"]["ubz_id"] for a in loaded.attempts], ids)

    def test_monitor_rejects_reused_pane_id_even_in_same_session(self):
        ch = self.make_challenge()
        unit = ch.attempts[0]
        unit["status"] = "running"
        unit["tmux"].update({"session": "ctf-x", "pane": "%1"})
        state = tmuxctl.PaneState(
            "ctf-x", "0", "dsh-tui", "/tmp/other", "different-attempt")

        with patch.object(monitor.tmuxctl, "capture",
                          side_effect=AssertionError("不得抓取串台 pane")):
            monitor.Monitor({})._poll_unit(ch, unit, {"%1": state})

        self.assertEqual(unit["status"], "pane_gone")

    def test_spawn_terminal_refuses_identity_mismatch(self):
        tm = {"session": "ctf-x", "window": "0", "pane": "%1",
              "ubz_id": "claude-attempt"}
        state = tmuxctl.PaneState("ctf-x", "0", "dsh-tui", "/tmp/dsh", "dsh-attempt")
        with patch.object(tmuxctl, "pane_states", return_value={"%1": state}), \
             patch.object(tmuxctl, "has_session") as has_session:
            with self.assertRaisesRegex(tmuxctl.TmuxError, "身份已变化"):
                tmuxctl.spawn_terminal("gnome-terminal", tm)
        has_session.assert_not_called()

    def test_kill_refuses_reused_pane_id(self):
        state = tmuxctl.PaneState("ctf-x", "0", "dsh-tui", "/tmp/dsh", "dsh-attempt")
        with patch.object(tmuxctl, "pane_states", return_value={"%1": state}), \
             patch.object(tmuxctl, "_run") as run:
            tmuxctl.kill_pane("%1", "ctf-x", "claude-attempt")
        run.assert_not_called()

    def test_resume_reallocates_stale_pane_and_restores_environment(self):
        ch = self.make_challenge()
        unit = ch.attempts[0]
        uid = unit["tmux"]["ubz_id"]
        unit.update({"status": "exited", "prompt_sent": True})
        unit["tmux"].update({"session": ch.tmux["session"], "pane": "%1"})
        ch.save()
        new_pane = {"session": ch.tmux["session"], "window": "3", "pane": "%9"}

        with patch.object(server.tmuxctl, "pane_exists", return_value=False), \
             patch.object(server.tmuxctl, "allocate_pane", return_value=new_pane) as allocate, \
             patch.object(server.tmuxctl, "send_command") as send_command, \
             patch.object(server.tmuxctl, "launch_harness") as launch, \
             patch.object(server.harness, "wait_ready"), \
             patch.object(server.harness, "nudge_to_continue"):
            asyncio.run(server._resume_unit(ch, unit))

        self.assertEqual(unit["tmux"]["pane"], "%9")
        self.assertEqual(unit["tmux"]["ubz_id"], uid)
        self.assertEqual(allocate.call_args.kwargs["ubz_id"], uid)
        env = send_command.call_args.args[1]
        self.assertIn(f"UBZ_PORT_BASE={unit['port_base']}", env)
        self.assertIn(f"UBZ_PORT_END={unit['port_base'] + 999}", env)
        self.assertIn(f"UBZ_INSTANCE_ID={uid}", env)
        self.assertIn("UBZ_BOARD_BIN=", env)
        self.assertIn("UBZ_BOARD_FILE=", env)
        self.assertIn("UBZ_WORKDIR=", env)
        self.assertIn("/bin:", env)
        self.assertIn("claude -c", launch.call_args.args[1])
        self.assertEqual(store.Challenge.load(ch.meta_path).attempts[0]["tmux"]["ubz_id"], uid)

    def test_resume_never_injects_into_running_foreign_process(self):
        ch = self.make_challenge()
        unit = ch.attempts[0]
        unit.update({"status": "exited", "prompt_sent": True})
        unit["tmux"].update({"session": "ctf-x", "pane": "%1"})
        with patch.object(server.tmuxctl, "pane_exists", return_value=True), \
             patch.object(server.tmuxctl, "pane_current_command", return_value="dsh-tui"), \
             patch.object(server.tmuxctl, "send_command") as send_command, \
             patch.object(server.tmuxctl, "allocate_pane") as allocate:
            with self.assertRaisesRegex(ValueError, "拒绝注入"):
                asyncio.run(server._resume_unit(ch, unit))
        send_command.assert_not_called()
        allocate.assert_not_called()

    def test_migration_only_adopts_pane_with_matching_cwd(self):
        good = self.make_challenge("good")
        bad = self.make_challenge("bad", "dsh")
        good_unit = good.attempts[0]
        bad_unit = bad.attempts[0]
        for ch, unit, pane in ((good, good_unit, "%1"), (bad, bad_unit, "%2")):
            unit["tmux"] = {"session": "ctf-x", "pane": pane}
            ch.save()
        states = {
            "%1": tmuxctl.PaneState("ctf-x", "0", "claude", good_unit["workdir"], ""),
            "%2": tmuxctl.PaneState("ctf-x", "1", "dsh-tui", "/tmp/unrelated", ""),
        }
        roots = {"current_root": self.root,
                 "recent_roots": [{"path": self.root, "exists": True}]}
        with patch.object(server.tmuxctl, "pane_states", return_value=states), \
             patch.object(server.tmuxctl, "tag_pane") as tag, \
             patch.object(server.store, "list_roots", return_value=roots):
            stats = server._migrate_tmux_identities()

        self.assertEqual(stats["new_ids"], 2)
        self.assertEqual(stats["adopted"], 1)
        tag.assert_called_once()
        self.assertEqual(tag.call_args.args[0], "%1")
        self.assertTrue(store.Challenge.load(good.meta_path).attempts[0]["tmux"]["ubz_id"])
        self.assertTrue(store.Challenge.load(bad.meta_path).attempts[0]["tmux"]["ubz_id"])
    def test_duplicate_launch_is_idempotent(self):
        ch = self.make_challenge("duplicate")
        unit = ch.attempts[0]
        calls = []

        async def fake_launch(_ch, att, _stagger=0.0):
            calls.append(att["id"])
            att["status"] = "launching"
            att["tmux"]["pane"] = "%9"
            await asyncio.sleep(0.02)
            att["status"] = "running"
            server._save_unit_state(_ch, att)

        other = store.Challenge.load(ch.meta_path)   # 第二个请求持有独立旧副本
        with patch.object(server, "_launch_attempt_locked", side_effect=fake_launch), \
             patch.object(server, "_unit_pane_exists", return_value=True):
            async def launch_twice():
                await asyncio.gather(
                    server._launch_attempt(ch, unit),
                    server._launch_attempt(other, other.attempts[0]),
                )
            asyncio.run(launch_twice())
        self.assertEqual(calls, [unit["id"]])

    def test_output_only_poll_does_not_rewrite_meta(self):
        ch = self.make_challenge("quiet")
        unit = ch.attempts[0]
        ch.status = unit["status"] = "running"
        unit["tmux"].update({"session": "ctf-x", "pane": "%1"})
        ch.board_updated = (Path(ch.workdir) / "board.md").stat().st_mtime
        ch.save()
        before = ch.meta_path.read_bytes()

        m = monitor.Monitor({})
        with patch.object(monitor.tmuxctl, "pane_exists", return_value=True), \
             patch.object(monitor.tmuxctl, "pane_current_command", return_value="claude"), \
             patch.object(monitor.tmuxctl, "capture", return_value="lots of new output\n"):
            m._poll_challenge(ch)

        self.assertEqual(ch.meta_path.read_bytes(), before)
        uid = unit["tmux"]["ubz_id"]
        self.assertEqual(m._round_outputs[ch.root][uid], "lots of new output")


if __name__ == "__main__":
    unittest.main()
