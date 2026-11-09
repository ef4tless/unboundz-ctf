import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server
from core import store


class CompetitionModeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        for name, value in (("APP_DIR", Path(self.root) / ".state"),
                            ("STATE_FILE", Path(self.root) / ".state" / "state.json")):
            p = patch.object(store, name, value)
            p.start()
            self.addCleanup(p.stop)
        server._DASHBOARD_META_CACHE.clear()
        server._DASHBOARD_HISTORY.clear()

    def test_traditional_mode_never_scans_adapters_or_tokens(self):
        store.set_root(self.root)
        self.assertEqual(store.get_competition_mode(), store.MODE_TRADITIONAL)
        with patch.object(server.contest_mod, "list_adapters",
                          side_effect=AssertionError("传统模式不应扫描适配器")), \
             patch.object(server.store, "get_contest_token",
                          side_effect=AssertionError("传统模式不应读取 Token")):
            result = server.list_contests()
        self.assertEqual(result["contests"], [])
        self.assertEqual(result["competition_mode"], store.MODE_TRADITIONAL)
        with self.assertRaises(Exception):
            server._require_api_auto(self.root)

    def test_legacy_bound_root_is_inferred_as_api_auto(self):
        ch = store.create_challenge(self.root, name="bound", category="misc",
                                    harnesses=["claude"])
        ch.contest = {"adapter": "mock-ai", "question_id": "Q1"}
        ch.save()
        store.set_root(self.root)
        self.assertEqual(store.get_competition_mode(), store.MODE_API_AUTO)

    def test_tokens_and_hosts_are_scoped_by_root(self):
        other = str(Path(self.root) / "other")
        Path(other).mkdir()
        store.set_contest_token("mock-ai", "legacy-token")
        store.set_contest_token("mock-ai", "token-a", self.root)
        store.set_contest_token("mock-ai", "token-b", other)
        store.set_contest_host("mock-ai", self.root, "https://a.example/")
        store.set_contest_host("mock-ai", other, "https://b.example")

        self.assertEqual(store.get_contest_token("mock-ai", self.root), "token-a")
        self.assertEqual(store.get_contest_token("mock-ai", other), "token-b")
        self.assertEqual(store.get_contest_host("mock-ai", self.root), "https://a.example")
        store.set_contest_token("mock-ai", "", self.root)
        self.assertEqual(store.get_contest_token("mock-ai", self.root), "")
        self.assertEqual(store.get_contest_token("mock-ai", other), "token-b")

    def test_traditional_submit_is_rejected_before_loading_adapter(self):
        ch = store.create_challenge(self.root, name="traditional", category="misc",
                                    harnesses=["claude"])
        ch.contest = {"adapter": "mock-ai", "question_id": "Q1"}
        ch.save()
        store.set_root(self.root, competition_mode=store.MODE_TRADITIONAL)
        with patch.object(server, "_get", return_value=ch), \
             patch.object(server.contest_mod, "load_adapter",
                          side_effect=AssertionError("传统模式不应加载适配器")):
            with self.assertRaises(Exception) as ctx:
                server.submit_flag(ch.id, server.FlagIn(flag="flag{x}"))
        self.assertIn("传统 CTF", str(ctx.exception))

    def test_dashboard_mode_change_invalidates_revision(self):
        store.create_challenge(self.root, name="one", category="misc",
                               harnesses=["claude"])
        store.set_root(self.root)
        first = server._dashboard_snapshot(self.root, "", "dashboard")
        store.set_competition_mode(self.root, store.MODE_API_AUTO)
        second = server._dashboard_snapshot(
            self.root, first["revision"], "dashboard")
        self.assertNotEqual(first["revision"], second["revision"])
        self.assertEqual(second["competition_mode"], store.MODE_API_AUTO)
        self.assertFalse(second["unchanged"])


if __name__ == "__main__":
    unittest.main()
