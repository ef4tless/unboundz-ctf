import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import server
from core import monitor, store, tmuxctl


class DashboardSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        server._DASHBOARD_META_CACHE.clear()
        server._DASHBOARD_HISTORY.clear()
        self.addCleanup(server._DASHBOARD_META_CACHE.clear)
        self.addCleanup(server._DASHBOARD_HISTORY.clear)

    def make_challenge(self, name="one"):
        ch = store.create_challenge(
            self.root, name=name, category="custom", custom_prompt="完整私有提示词",
            harnesses=["codex", "dsh"],
        )
        for i, attempt in enumerate(ch.attempts):
            attempt["last_output"] = f"{name} attempt {i}\n" + ("output\n" * 20)
        ch.save()
        return ch

    def snapshot(self, since="", view="dashboard", output_since=0):
        with patch.object(server.store, "get_root", return_value=self.root):
            return server.list_challenges(
                since=since, view=view, output_since=output_since)

    def test_dashboard_view_is_slim_but_default_api_stays_complete(self):
        ch = self.make_challenge()
        ch.vuln_points = ["- [verified] stack overflow"]
        ch.save()

        full = self.snapshot(view="full")
        self.assertEqual(full["challenges"][0]["custom_prompt"], "完整私有提示词")
        self.assertIn("vuln_points", full["challenges"][0])

        slim = self.snapshot(view="dashboard")
        card = slim["challenges"][0]
        self.assertNotIn("custom_prompt", card)
        self.assertNotIn("defense_prompt", card)
        self.assertNotIn("vuln_points", card)
        self.assertNotIn("last_output", card)
        self.assertEqual(card["vuln_count"], 1)
        self.assertNotIn("last_output", card["attempts"][0])
        self.assertNotIn("prompt_sent", card["attempts"][0])
        self.assertNotEqual(full["revision"], slim["revision"])

    def test_unchanged_revision_does_not_reload_any_meta(self):
        self.make_challenge()
        first = self.snapshot()

        with patch.object(server.store.Challenge, "load",
                          side_effect=AssertionError("不应重读 meta")):
            second = self.snapshot(since=first["revision"])

        self.assertTrue(second["unchanged"])
        self.assertTrue(second["delta"])
        self.assertEqual(second["challenges"], [])
        self.assertEqual(second["removed"], [])
        self.assertEqual(second["revision"], first["revision"])

    def test_output_revision_updates_preview_without_meta_delta(self):
        ch = self.make_challenge()
        first = self.snapshot()
        uid = ch.attempts[0]["tmux"]["ubz_id"]
        with patch.object(server.MONITOR, "output_revision", 7), \
             patch.object(server.MONITOR, "outputs",
                          {self.root: {uid: "recent line 1\nrecent line 2"}}):
            changed = self.snapshot(since=first["revision"], output_since=0)
            self.assertFalse(changed["unchanged"])
            self.assertEqual(changed["challenges"], [])
            self.assertEqual(changed["outputs"][uid], "recent line 1\nrecent line 2")
            self.assertEqual(changed["output_revision"], 7)

            unchanged = self.snapshot(since=first["revision"], output_since=7)
            self.assertTrue(unchanged["unchanged"])
            self.assertNotIn("outputs", unchanged)

    def test_single_changed_challenge_is_the_only_one_loaded_and_returned(self):
        changed = self.make_challenge("changed")
        self.make_challenge("untouched")
        first = self.snapshot()
        changed.note = "一条明显变长的新状态说明"
        changed.save()

        with patch.object(server, "_dashboard_load",
                          wraps=server._dashboard_load) as load:
            delta = self.snapshot(since=first["revision"])

        self.assertEqual(load.call_count, 1)
        self.assertEqual(Path(load.call_args.args[0]), changed.meta_path)
        self.assertFalse(delta["unchanged"])
        self.assertTrue(delta["delta"])
        self.assertEqual([c["id"] for c in delta["challenges"]], [changed.id])
        self.assertEqual(delta["challenges"][0]["note"], changed.note)
        self.assertEqual(delta["removed"], [])

    def test_deleted_challenge_is_reported_without_full_reload(self):
        deleted = self.make_challenge("deleted")
        kept = self.make_challenge("kept")
        first = self.snapshot()
        deleted.meta_path.unlink()

        with patch.object(server, "_dashboard_load",
                          wraps=server._dashboard_load) as load:
            delta = self.snapshot(since=first["revision"])

        load.assert_not_called()
        self.assertTrue(delta["delta"])
        self.assertEqual(delta["removed"], [deleted.id])
        self.assertEqual(delta["challenges"], [])
        followup = self.snapshot(since=delta["revision"])
        self.assertTrue(followup["unchanged"])
        self.assertEqual(kept.id, first["challenges"][1]["id"])

    def test_missing_history_falls_back_to_full_snapshot(self):
        changed = self.make_challenge("changed")
        untouched = self.make_challenge("untouched")
        first = self.snapshot()
        changed.note = "缓存丢失期间发生的变化"
        changed.save()
        server._DASHBOARD_HISTORY.clear()

        fallback = self.snapshot(since=first["revision"])

        self.assertFalse(fallback["delta"])
        self.assertEqual({c["id"] for c in fallback["challenges"]},
                         {changed.id, untouched.id})

    def test_no_root_keeps_original_empty_response_shape(self):
        with patch.object(server.store, "get_root", return_value=None):
            result = server.list_challenges(view="dashboard")
        self.assertIsNone(result["root"])
        self.assertEqual(result["challenges"], [])
        self.assertNotIn("tmux_session", result)


class TmuxSnapshotTests(unittest.TestCase):
    def test_pane_states_parses_one_batch_query(self):
        with patch.object(tmuxctl, "_run", return_value=(
                "%1\tctf-a\t0\tcodex\t/tmp/a\tid-a\n"
                "%2\tctf-b\t1\tzsh\t/tmp/b\tid-b\n")) as run:
            states = tmuxctl.pane_states()

        self.assertEqual(states, {
            "%1": tmuxctl.PaneState("ctf-a", "0", "codex", "/tmp/a", "id-a"),
            "%2": tmuxctl.PaneState("ctf-b", "1", "zsh", "/tmp/b", "id-b"),
        })
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0][:2], ["list-panes", "-a"])

    def test_poll_unit_reuses_snapshot_without_per_pane_probes(self):
        with tempfile.TemporaryDirectory() as root:
            ch = store.create_challenge(root, name="one", category="misc",
                                        harnesses=["codex"])
            unit = ch.attempts[0]
            unit["status"] = "running"
            unit["tmux"] = {"session": "ctf-x", "pane": "%7"}
            m = monitor.Monitor({})
            with patch.object(monitor.tmuxctl, "capture", return_value="working\n"), \
                 patch.object(monitor.tmuxctl, "pane_exists",
                              side_effect=AssertionError("不应逐路 list-panes")), \
                 patch.object(monitor.tmuxctl, "pane_current_command",
                              side_effect=AssertionError("不应逐路查前台进程")):
                m._poll_unit(ch, unit, {
                    "%7": tmuxctl.PaneState("ctf-x", "0", "codex", root, "")
                })

            self.assertEqual(unit["status"], "running")

    def test_poll_once_takes_only_one_pane_snapshot(self):
        ch = SimpleNamespace(id="c1", root="/tmp/other", status="running")
        states = {"%1": tmuxctl.PaneState("ctf-x", "0", "codex", "/tmp/x", "id-1")}
        m = monitor.Monitor({})
        with patch.object(monitor.store, "all_active_challenges", return_value=[ch]), \
             patch.object(monitor.store, "get_root", return_value="/tmp/current"), \
             patch.object(monitor.tmuxctl, "pane_states", return_value=states) as probe, \
             patch.object(m, "_poll_challenge") as poll:
            asyncio.run(m.poll_once())

        probe.assert_called_once_with()
        poll.assert_called_once_with(ch, states)
        self.assertEqual(m.elsewhere_running, 1)


if __name__ == "__main__":
    unittest.main()
