import asyncio
import concurrent.futures
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import server
from core import downloader, monitor, store, tmuxctl


class ConcurrentStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_concurrent_saves_are_atomic_and_readable(self):
        def make(i):
            return store.Challenge(
                id=f"c{i:03d}", name=f"chall-{i}", category="misc",
                workdir=self.root, root=self.root,
                note=f"writer-{i}-" + ("x" * 10000),
                last_output="y" * 30000)

        errors = []
        def save(i):
            try:
                make(i).save()
            except Exception as exc:  # pragma: no cover - 失败时输出具体原因
                errors.append(exc)

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            list(pool.map(save, range(80)))
        self.assertEqual(errors, [])
        self.assertTrue(store.Challenge.load(make(0).meta_path).note)

    def test_concurrent_add_attempts_get_unique_ids_dirs_and_ports(self):
        original = store.create_challenge(
            self.root, name="add-race", category="misc", harnesses=["claude"])
        other = store.Challenge.load(original.meta_path)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(store.add_attempt, ch, harness)
                       for ch, harness in ((original, "dsh"), (other, "kimi"))]
            [f.result() for f in futures]

        ch = store.Challenge.load(original.meta_path)
        self.assertEqual(len(ch.attempts), 3)
        self.assertEqual(len({a["id"] for a in ch.attempts}), 3)
        self.assertEqual(len({a["workdir"] for a in ch.attempts}), 3)
        self.assertEqual(len({a["port_base"] for a in ch.attempts}), 3)

    def test_listing_cache_reuses_unchanged_files_but_returns_independent_objects(self):
        store.create_challenge(self.root, name="cached", category="misc",
                               harnesses=["claude"])
        first = store.list_challenges(self.root)
        with patch.object(Path, "read_text",
                          side_effect=AssertionError("未变化的 meta 不应重读")):
            second = store.list_challenges(self.root)
        self.assertIsNot(first[0], second[0])
        second[0].name = "changed-in-memory"
        self.assertNotEqual(first[0].name, second[0].name)


class LaunchGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        server._launch_limiters.clear()
        self.addCleanup(server._launch_limiters.clear)

    def test_global_launch_limit_and_health_counters(self):
        challenges = [store.create_challenge(
            self.root, name=f"gate-{i}", category="misc", harnesses=["claude"])
            for i in range(6)]
        running = 0
        maximum = 0

        async def fake_launch(ch, att, _stagger=0.0):
            nonlocal running, maximum
            running += 1
            maximum = max(maximum, running)
            att["status"] = "launching"
            await asyncio.sleep(0.03)
            att["status"] = "running"
            att["tmux"]["pane"] = f"%{att['port_base']}"
            server._save_unit_state(ch, att)
            running -= 1

        async def launch_all():
            with patch.dict(server.CONFIG, {"launch_concurrency": 2}), \
                 patch.object(server, "_launch_attempt_locked", side_effect=fake_launch):
                await asyncio.gather(*(
                    server._launch_attempt(ch, ch.attempts[0]) for ch in challenges))

        asyncio.run(launch_all())
        self.assertEqual(maximum, 2)
        health = server.get_health()
        self.assertEqual(health["launch"]["active"], 0)
        self.assertEqual(health["launch"]["waiting"], 0)
        self.assertEqual(health["launch"]["limit"], 2)


class MonitorReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_idle_challenge_uses_slow_poll_interval(self):
        ch = store.create_challenge(self.root, name="idle", category="misc",
                                    harnesses=["claude"])
        ch.status = ch.attempts[0]["status"] = "exited"
        m = monitor.Monitor({"idle_poll_interval": 20})
        with patch.object(monitor.store, "all_active_challenges", return_value=[ch]), \
             patch.object(monitor.store, "get_root", return_value=self.root), \
             patch.object(monitor.tmuxctl, "pane_states", return_value={}), \
             patch.object(m, "_poll_challenge") as poll:
            asyncio.run(m.poll_once())
            asyncio.run(m.poll_once())
        poll.assert_called_once()

    def test_capture_line_limit_is_configurable(self):
        ch = store.create_challenge(self.root, name="capture", category="misc",
                                    harnesses=["claude"])
        unit = ch.attempts[0]
        unit["status"] = "running"
        unit["tmux"].update({"session": "ctf-x", "pane": "%1"})
        uid = unit["tmux"]["ubz_id"]
        state = tmuxctl.PaneState("ctf-x", "0", "claude", unit["workdir"], uid)
        with patch.object(monitor.tmuxctl, "capture", return_value="working\n") as capture:
            monitor.Monitor({"capture_lines": 80})._poll_unit(ch, unit, {"%1": state})
        self.assertEqual(capture.call_args.kwargs["lines"], 80)


class SessionMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_same_basename_gets_different_session_names(self):
        a = store.session_name_for_root(str(Path(self.root) / "a" / "2026ycb"))
        b = store.session_name_for_root(str(Path(self.root) / "b" / "2026ycb"))
        self.assertNotEqual(a, b)
        self.assertTrue(a.startswith("ctf-2026ycb-"))

    def test_legacy_session_is_renamed_without_changing_attempt_uuid(self):
        ch = store.create_challenge(self.root, name="migrate", category="misc",
                                    harnesses=["claude"])
        unit = ch.attempts[0]
        legacy = store._legacy_session_name_for_root(self.root)
        expected = store.session_name_for_root(self.root)
        uid = unit["tmux"]["ubz_id"]
        ch.tmux["session"] = legacy
        unit["tmux"].update({"session": legacy, "pane": "%1"})
        ch.save()
        states = {"%1": tmuxctl.PaneState(
            legacy, "0", "claude", unit["workdir"], uid)}
        roots = {"current_root": self.root,
                 "recent_roots": [{"path": self.root, "exists": True}]}
        with patch.object(server.tmuxctl, "pane_states", return_value=states), \
             patch.object(server.tmuxctl, "has_session", side_effect=lambda s: s == legacy), \
             patch.object(server.tmuxctl, "rename_session") as rename, \
             patch.object(server.store, "list_roots", return_value=roots):
            server._migrate_tmux_identities()

        rename.assert_called_once_with(legacy, expected)
        saved = store.Challenge.load(ch.meta_path)
        self.assertEqual(saved.tmux["session"], expected)
        self.assertEqual(saved.attempts[0]["tmux"]["session"], expected)
        self.assertEqual(saved.attempts[0]["tmux"]["ubz_id"], uid)
        self.assertEqual(states["%1"].session, expected)


class DownloadCancellationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_cancel_stops_chunk_loop_without_final_save(self):
        ch = store.create_challenge(
            self.root, name="download", category="misc", harnesses=["claude"],
            attachment_urls=["http://example.invalid/attachment.zip"])
        ch.status = "downloading"
        ch.save()
        cancel = threading.Event()

        class Response:
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def raise_for_status(self): return None
            def iter_content(self, _size):
                yield b"first"
                cancel.set()
                yield b"second"

        with patch.object(downloader.requests, "get", return_value=Response()):
            with self.assertRaises(downloader.DownloadCancelled):
                downloader.download_all(ch, {}, cancel)
        saved = store.Challenge.load(ch.meta_path)
        self.assertEqual(saved.download_status, "pending")
        self.assertNotEqual(saved.download_status, "done")

    def test_deleted_challenge_is_not_recreated(self):
        ch = store.create_challenge(
            self.root, name="deleted-download", category="misc", harnesses=["claude"],
            attachment_urls=["http://example.invalid/a.zip"])
        ch.meta_path.unlink()
        with self.assertRaises(downloader.DownloadCancelled):
            downloader.download_all(ch, {})
        self.assertFalse(ch.meta_path.exists())


if __name__ == "__main__":
    unittest.main()
