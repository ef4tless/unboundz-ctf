import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server
from core import store


class AttemptModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_create_with_multiple_harnesses(self):
        ch = store.create_challenge(self.root, name="t1", category="pwn",
                                    harnesses=["codex", "dsh"])
        self.assertEqual([a["harness"] for a in ch.attempts], ["codex", "dsh"])
        a0, a1 = ch.attempts
        # 各自独立工作目录 runs/<h>/, 端口段按序分配
        self.assertTrue(a0["workdir"].endswith("runs/codex"))
        self.assertTrue(a1["workdir"].endswith("runs/dsh"))
        self.assertEqual(a0["port_base"], 30000)
        self.assertEqual(a1["port_base"], 31000)
        # 目录与共享链接就绪: board.md 是指向主目录的符号链接,
        # attachments 是各路的真目录(实体拷贝, IDA 等工具不能共享同一文件)
        board = Path(self.root) / "t1" / "board.md"
        self.assertTrue(board.is_file())
        for a in (a0, a1):
            wd = Path(a["workdir"])
            self.assertTrue(wd.is_dir())
            self.assertEqual(os.path.realpath(wd / "board.md"),
                             os.path.realpath(board))
            self.assertTrue((wd / "attachments").is_dir())
            self.assertFalse((wd / "attachments").is_symlink())
        # 落盘后再读回一致
        again = store.Challenge.load(ch.meta_path)
        self.assertEqual(len(again.attempts), 2)

    def test_duplicate_harness_gets_suffixed_dir(self):
        ch = store.create_challenge(self.root, name="t2", category="misc",
                                    harnesses=["codex"])
        att = store.add_attempt(ch, "codex")
        self.assertTrue(att["workdir"].endswith("runs/codex-2"))
        self.assertEqual(att["port_base"], 31000)

    def test_add_attempt_converts_legacy_challenge(self):
        ch = store.Challenge(
            id="leg123", name="old", category="web", harness="claude",
            workdir=str(Path(self.root) / "old"), root=self.root,
            tmux={"session": "ctf-x", "pane": "%9"}, status="running",
            exit_seen=2, prompt_sent=True, last_output="tail", note="n")
        Path(ch.workdir).mkdir(parents=True)
        ch.save()

        att = store.add_attempt(ch, "dsh")

        self.assertEqual(len(ch.attempts), 2)
        legacy, _ = ch.attempts
        self.assertEqual(legacy["id"], "a0")
        self.assertEqual(legacy["harness"], "claude")
        self.assertEqual(legacy["workdir"], ch.workdir)   # 旧路留在主目录
        self.assertEqual(legacy["tmux"]["pane"], "%9")
        self.assertEqual(legacy["exit_seen"], 2)
        self.assertTrue(legacy["prompt_sent"])
        self.assertTrue((Path(ch.workdir) / "board.md").is_file())
        self.assertTrue(att["workdir"].endswith("runs/dsh"))

    def test_aggregate_status(self):
        ch = store.create_challenge(self.root, name="t3", category="misc",
                                    harnesses=["codex", "dsh"])
        self.assertEqual(store.aggregate_status(ch), "ready")
        ch.attempts[0]["status"] = "exited"
        ch.attempts[1]["status"] = "running"
        self.assertEqual(store.aggregate_status(ch), "running")
        ch.attempts[1]["status"] = "need_help"
        self.assertEqual(store.aggregate_status(ch), "need_help")
        ch.flag = "flag{x}"
        self.assertEqual(store.aggregate_status(ch), "solved")

    def test_legacy_unit_view_roundtrip(self):
        ch = store.Challenge(id="l1", name="l", category="misc",
                             workdir=self.root, root=self.root,
                             tmux={"session": "s"}, status="running")
        units = store.unit_views(ch)
        self.assertEqual(len(units), 1)
        unit = units[0]
        self.assertTrue(unit["_legacy"])
        unit["status"] = "exited"
        unit["exit_seen"] = 3
        store.apply_unit(ch, unit)
        self.assertEqual(ch.status, "exited")
        self.assertEqual(ch.exit_seen, 3)

    def test_find_unit(self):
        ch = store.create_challenge(self.root, name="t4", category="misc",
                                    harnesses=["codex", "dsh"])
        self.assertEqual(store.find_unit(ch, "a1")["harness"], "dsh")
        with self.assertRaises(ValueError):
            store.find_unit(ch, "a9")
        with self.assertRaises(ValueError):   # 多路不带 aid 报错
            store.find_unit(ch, "")
        legacy = store.Challenge(id="l2", name="l", category="misc",
                                 workdir=self.root, root=self.root)
        self.assertEqual(store.find_unit(legacy, "")["harness"], legacy.harness)


    def test_sync_attempt_attachments_copies_and_isolates(self):
        ch = store.create_challenge(self.root, name="t5", category="pwn",
                                    harnesses=["codex", "dsh"])
        main_att = Path(ch.workdir) / "attachments"
        (main_att / "sub").mkdir()
        (main_att / "sub" / "pwn").write_bytes(b"\x7fELF fake")
        (main_att / "note.txt").write_text("v1", encoding="utf-8")

        copied = store.sync_attempt_attachments(ch)
        self.assertEqual(copied, 4)   # 2 文件 × 2 路
        a0_file = Path(ch.attempts[0]["workdir"]) / "attachments" / "sub" / "pwn"
        a1_file = Path(ch.attempts[1]["workdir"]) / "attachments" / "sub" / "pwn"
        self.assertEqual(a0_file.read_bytes(), b"\x7fELF fake")
        self.assertNotEqual(a0_file.stat().st_ino, a1_file.stat().st_ino)  # 实体隔离
        # 改一路的拷贝不影响主目录和其他路
        a0_file.write_bytes(b"patched")
        self.assertEqual((main_att / "sub" / "pwn").read_bytes(), b"\x7fELF fake")
        self.assertEqual(a1_file.read_bytes(), b"\x7fELF fake")
        # 增量: 只拷缺失的; 已存在的一律不覆盖(可能是该路自己 patch 过的版本)
        self.assertEqual(store.sync_attempt_attachments(ch), 0)
        self.assertEqual(a0_file.read_bytes(), b"patched")   # patch 不被冲掉
        (main_att / "note.txt").write_text("v2-longer", encoding="utf-8")  # 同名更新不传播
        self.assertEqual(store.sync_attempt_attachments(ch), 0)
        (main_att / "libc.so.6").write_bytes(b"libc")        # 新文件会传播
        self.assertEqual(store.sync_attempt_attachments(ch), 2)
        self.assertEqual((Path(ch.attempts[1]["workdir"])
                          / "attachments" / "libc.so.6").read_bytes(), b"libc")

    def test_sync_replaces_legacy_attachment_symlink(self):
        ch = store.create_challenge(self.root, name="t6", category="misc",
                                    harnesses=["codex"])
        # 模拟早期布局: attachments 是符号链接
        att_dir = Path(ch.attempts[0]["workdir"]) / "attachments"
        att_dir.rmdir()
        os.symlink(os.path.join("..", "..", "attachments"), att_dir)
        (Path(ch.workdir) / "attachments" / "f.bin").write_bytes(b"xx")
        self.assertEqual(store.sync_attempt_attachments(ch), 1)
        self.assertFalse(att_dir.is_symlink())
        self.assertEqual((att_dir / "f.bin").read_bytes(), b"xx")


class AttemptEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def make_multi(self, statuses=("running", "running")):
        ch = store.create_challenge(self.root, name="multi", category="misc",
                                    harnesses=["codex", "dsh"])
        for i, (a, s) in enumerate(zip(ch.attempts, statuses)):
            a["status"] = s
            a["tmux"] = {"session": "t", "pane": f"%1{i}"}
        ch.save()
        return ch

    def test_set_flag_default_keeps_attempts_running(self):
        ch = self.make_multi()
        with (
            patch.object(server, "_get", return_value=ch),
            patch.object(server.tmuxctl, "pane_exists", return_value=True),
            patch.object(server.tmuxctl, "pane_current_command", return_value="codex"),
            patch.object(server.tmuxctl, "interrupt_pane") as intr,
        ):
            result = server.set_flag(ch.id, server.FlagIn(flag="flag{w}"))
        self.assertEqual(result["status"], "solved")
        intr.assert_not_called()   # flag 可能有错/要写 writeup, 默认不停任何一路

    def test_set_flag_with_stop_others_interrupts_running_attempts(self):
        ch = self.make_multi()
        interrupted = []

        def fake_interrupt(pane, times=2, **_kwargs):
            interrupted.append(pane)

        with (
            patch.object(server, "_get", return_value=ch),
            patch.object(server.tmuxctl, "pane_exists", return_value=True),
            patch.object(server.tmuxctl, "pane_current_command",
                         side_effect=["codex", "zsh"]),  # 第二路已退回 shell
            patch.object(server.tmuxctl, "interrupt_pane",
                         side_effect=fake_interrupt),
        ):
            server.set_flag(ch.id, server.FlagIn(flag="flag{w}", stop_others=True))
        self.assertEqual(interrupted, ["%10"])   # 只停真正在跑的那一路

    def test_flag_attempt_attribution(self):
        ch = self.make_multi()
        with (
            patch.object(server, "_get", return_value=ch),
            patch.object(server.tmuxctl, "pane_exists", return_value=False),
        ):
            result = server.set_flag(
                ch.id, server.FlagIn(flag="flag{w}", attempt="a1"))
            self.assertEqual(result["flag_attempt"], "a1")
            # 清空 flag 时归属一并清掉
            result = server.set_flag(ch.id, server.FlagIn(flag=""))
            self.assertEqual(result["flag_attempt"], "")
            # 不存在的 aid 报错且不落 flag
            with self.assertRaises(Exception) as ctx:
                server.set_flag(ch.id, server.FlagIn(flag="flag{x}", attempt="a9"))
            self.assertIn("未知 attempt", str(ctx.exception))
            self.assertEqual(store.Challenge.load(ch.meta_path).flag, "")

    def test_attempts_endpoint_rejects_unknown_harness(self):
        ch = self.make_multi()
        with patch.object(server, "_get", return_value=ch):
            with self.assertRaises(Exception) as ctx:
                import asyncio
                asyncio.run(server.add_attempt(
                    ch.id, server.AttemptIn(harness="nope", auto_launch=False)))
        self.assertIn("未配置", str(ctx.exception))

    def test_attempts_endpoint_creates_without_launch(self):
        ch = self.make_multi()
        with patch.object(server, "_get", return_value=ch):
            import asyncio
            result = asyncio.run(server.add_attempt(
                ch.id, server.AttemptIn(harness="claude", auto_launch=False)))
        attempts = result["attempts"]
        self.assertEqual(len(attempts), 3)
        self.assertEqual(attempts[-1]["harness"], "claude")
        self.assertEqual(attempts[-1]["status"], "ready")
        self.assertEqual(attempts[-1]["port_base"], 32000)


import os  # noqa: E402  (realpath 断言要用)


class CollabFilesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_single_attempt_also_lands_collab_files_for_future_relay(self):
        ch = store.create_challenge(self.root, name="s1", category="misc",
                                    harnesses=["codex"])
        main = Path(ch.workdir)
        self.assertTrue((main / "AGENTS.md").is_file())
        self.assertTrue((main / "CLAUDE.md").is_symlink())
        self.assertTrue((main / "GEMINI.md").is_symlink())
        wd = Path(ch.attempts[0]["workdir"])
        self.assertEqual(os.path.realpath(wd / "AGENTS.md"),
                         os.path.realpath(main / "AGENTS.md"))
        self.assertEqual(os.path.realpath(wd / "GEMINI.md"),
                         os.path.realpath(main / "AGENTS.md"))

    def test_second_attempt_lands_collab_files(self):
        ch = store.create_challenge(self.root, name="s2", category="misc",
                                    harnesses=["codex"])
        store.add_attempt(ch, "dsh")
        main = Path(ch.workdir)
        # 主目录: AGENTS.md 真身 + CLAUDE.md / GEMINI.md 符号链接
        self.assertTrue((main / "AGENTS.md").is_file())
        self.assertTrue((main / "CLAUDE.md").is_symlink())
        self.assertTrue((main / "GEMINI.md").is_symlink())
        self.assertIn("board.md", (main / "AGENTS.md").read_text(encoding="utf-8"))
        # 每路工作目录都链接得到
        for a in ch.attempts:
            wd = Path(a["workdir"])
            self.assertEqual(os.path.realpath(wd / "AGENTS.md"),
                             os.path.realpath(main / "AGENTS.md"))
            self.assertEqual(os.path.realpath(wd / "CLAUDE.md"),
                             os.path.realpath(main / "AGENTS.md"))
            self.assertEqual(os.path.realpath(wd / "GEMINI.md"),
                             os.path.realpath(main / "AGENTS.md"))

    def test_suffix_solo_vs_multi(self):
        solo = store.create_challenge(self.root, name="s3", category="misc",
                                      harnesses=["codex"])
        text = server._attempt_prompt(solo, solo.attempts[0])
        self.assertIn("接力记录", text)
        self.assertIn("30000-30999", text)
        self.assertNotIn("本题多路并行解题", text)
        multi = store.create_challenge(self.root, name="s4", category="misc",
                                       harnesses=["codex", "dsh"])
        text = server._attempt_prompt(multi, multi.attempts[1])
        self.assertIn("协作纪律", text)
        self.assertIn("31000-31999", text)   # a1 的端口段
        self.assertNotIn("队友成果", text)   # 空板不提接力

    def test_suffix_points_to_board_when_it_has_entries(self):
        ch = store.create_challenge(self.root, name="s5b", category="misc",
                                    harnesses=["codex", "dsh"])
        board = Path(ch.workdir) / "board.md"
        board.write_text("# b\n## Facts\n- [verified] x\n- y 已否证\n",
                         encoding="utf-8")
        text = server._attempt_prompt(ch, ch.attempts[1])
        self.assertIn("已有 2 条队友成果", text)
        self.assertIn("先读一遍 board.md", text)

    def test_attempt_directive_reaches_prompt(self):
        ch = store.create_challenge(self.root, name="s5c", category="misc",
                                    harnesses=["codex"])
        att = store.add_attempt(ch, "dsh",
                                directive="你是后加开的一路，先读板接力")
        self.assertEqual(att["directive"], "你是后加开的一路，先读板接力")
        text = server._attempt_prompt(ch, att)
        self.assertIn("该路附加指令：你是后加开的一路，先读板接力", text)

    def test_poll_board_stats(self):
        import time
        from core import monitor
        ch = store.create_challenge(self.root, name="s5", category="misc",
                                    harnesses=["codex", "dsh"])
        board = Path(ch.workdir) / "board.md"
        board.write_text("# b\n## Facts\n- [verified] x\n- y 已否证\n",
                         encoding="utf-8")
        self.assertTrue(monitor.Monitor({})._poll_board(ch))
        self.assertEqual(ch.board_entries, 2)
        self.assertGreater(ch.board_updated, 0)
        self.assertFalse(monitor.Monitor({})._poll_board(ch))   # 无变化不重复置脏


import os  # noqa: E402  (realpath 断言要用)


class AwdpDefenseTests(unittest.TestCase):
    """AWDP 攻防模式: pwn/web 的拓展勾选。攻击侧就是普通 CTF (渲染不变);
    防御路 (role=defense) 用防御提示词开跑, 修洞保服务不追 flag。
    auto_defense=False 维持创建即并行开防御路的旧行为; 默认 True 走漏洞点接力
    (见 VulnRelayTests), 创建时不开防御路。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def make_awdp(self, name="awd1", **kw):
        opts = dict(category="pwn", harnesses=["codex"],
                    defense_harnesses=["dsh"], awdp=True, auto_defense=False)
        opts.update(kw)
        return store.create_challenge(self.root, name=name, **opts)

    def test_create_with_defense_harnesses(self):
        ch = self.make_awdp()
        self.assertEqual([(a["harness"], a["role"]) for a in ch.attempts],
                         [("codex", "attack"), ("dsh", "defense")])
        # 防御路是普通的一路: 独立目录/端口段/共享黑板一样不少
        d = ch.attempts[1]
        self.assertTrue(d["workdir"].endswith("runs/dsh"))
        self.assertEqual(d["port_base"], 31000)
        self.assertTrue((Path(ch.workdir) / "board.md").is_file())
        # 落盘读回 role/awdp 不丢
        again = store.Challenge.load(ch.meta_path)
        self.assertEqual(again.attempts[1]["role"], "defense")
        self.assertTrue(again.awdp)

    def test_attack_side_is_plain_ctf(self):
        ch = self.make_awdp()
        atk = server._attempt_prompt(ch, ch.attempts[0])
        self.assertIn("flag.txt", atk)
        self.assertNotIn("防御专家", atk)          # 攻击侧模板渲染不变
        self.assertNotIn("update.tar.gz", atk)
        self.assertIn("协作纪律", atk)             # 多路协作指针照旧
        self.assertIn("漏洞点", atk)               # 接力说明: 一验证就写板 (系统注入段)

    def test_defense_prompt_uses_defense_template(self):
        ch = self.make_awdp()
        text = server._attempt_prompt(ch, ch.attempts[1])
        self.assertIn("防御", text)
        self.assertIn("patched/", text)          # 防御页脚: 交付补丁
        self.assertIn("update.tar.gz", text)     # 最终产物 + 上传交接
        self.assertNotIn("flag.txt", text)       # 防御路不要求写 flag
        self.assertIn("协作纪律", text)           # 仍是多路协作的一员
        self.assertIn("31000-31999", text)

    def test_defense_prompt_override_per_challenge(self):
        ch = self.make_awdp(name="awd2", defense_prompt="你是防御，只许看 board.md 修洞")
        text = server._attempt_prompt(ch, ch.attempts[1])
        self.assertIn("只许看 board.md 修洞", text)
        self.assertIn("update.tar.gz", text)     # 页脚照拼
        # 空串回退到模板文件
        ch.defense_prompt = ""
        self.assertIn("防御专家", server._attempt_prompt(ch, ch.attempts[1]))

    def test_defense_prompt_missing_template_raises(self):
        ch = store.create_challenge(self.root, name="awd3", category="re",
                                    harnesses=["codex"])
        att = store.add_attempt(ch, "dsh", role="defense")
        with self.assertRaises(ValueError):
            server._attempt_prompt(ch, att)

    def test_win_name_marks_defense(self):
        ch = self.make_awdp(name="awd4")
        self.assertEqual(server._win_name(ch, ch.attempts[0]), "awd4·codex")
        self.assertEqual(server._win_name(ch, ch.attempts[1]), "awd4·dsh·防")

    def test_old_meta_without_role_is_attack(self):
        ch = self.make_awdp(name="awd5")
        for a in ch.attempts:
            a.pop("role")                         # 模拟旧 meta 没有 role 字段
        self.assertEqual(server._win_name(ch, ch.attempts[1]), "awd5·dsh")
        self.assertIn("flag.txt", server._attempt_prompt(ch, ch.attempts[1]))

    def test_add_attempt_endpoint_rejects_defense_when_not_awdp(self):
        ch = store.create_challenge(self.root, name="awd6", category="pwn",
                                    harnesses=["codex"])   # 没勾 AWDP
        with patch.object(server, "_get", return_value=ch):
            with self.assertRaises(Exception) as ctx:
                import asyncio
                asyncio.run(server.add_attempt(
                    ch.id, server.AttemptIn(harness="dsh", role="defense",
                                            auto_launch=False)))
        self.assertIn("AWDP", str(ctx.exception))

    def test_add_attempt_endpoint_accepts_defense_for_awdp(self):
        ch = self.make_awdp(name="awd7", defense_harnesses=None)
        with patch.object(server, "_get", return_value=ch):
            import asyncio
            result = asyncio.run(server.add_attempt(
                ch.id, server.AttemptIn(harness="dsh", role="defense",
                                        auto_launch=False)))
        self.assertEqual(result["attempts"][-1]["role"], "defense")

    def test_defense_categories_listed_but_not_a_category(self):
        from core import prompts
        self.assertEqual(prompts.defense_categories(), ["pwn", "web"])
        self.assertNotIn("defense", prompts.categories())        # defense/ 不污染类型
        self.assertNotIn("awdp", prompts.categories())           # awdp 是勾选不是类型

    def test_defense_rules_rendered_into_prompt(self):
        rules = "修补路径 ['/home/ctf']；白名单命令 ['cp','mv','chmod']"
        ch = self.make_awdp(name="awd8", defense_rules=rules)
        text = server._attempt_prompt(ch, ch.attempts[1])
        self.assertIn(rules, text)
        # 攻击路不吃防御规则
        self.assertNotIn(rules, server._attempt_prompt(ch, ch.attempts[0]))
        # 落盘读回规则不丢
        self.assertEqual(store.Challenge.load(ch.meta_path).defense_rules, rules)

    def test_defense_rules_default_when_empty(self):
        ch = self.make_awdp(name="awd9")
        text = server._attempt_prompt(ch, ch.attempts[1])
        self.assertNotIn("{防御规则}", text)      # 变量一定被替换
        self.assertIn("/home/ctf", text)          # 空则给惯例兜底

    def test_defense_template_var(self):
        from core import prompts
        ch = self.make_awdp(name="awda")
        ch.defense_template = "update_tpl.tar.gz"
        text = server._attempt_prompt(ch, ch.attempts[1])
        self.assertIn("attachments/update_tpl.tar.gz", text)
        self.assertNotIn("{防御模板}", text)
        # 没传模板: 兜底文案, 变量照样替换掉
        ch.defense_template = ""
        text = server._attempt_prompt(ch, ch.attempts[1])
        self.assertNotIn("{防御模板}", text)

    def test_defense_template_upload_endpoint(self):
        import io
        from fastapi import UploadFile
        ch = self.make_awdp(name="awdb")
        uf = UploadFile(filename="update_tpl.tar.gz", file=io.BytesIO(b"tarbytes"))
        with patch.object(server, "_get", return_value=ch):
            import asyncio
            result = asyncio.run(server.upload_defense_template(ch.id, uf))
        self.assertEqual(result["saved"], "update_tpl.tar.gz")
        # 原始保存不解压, 文件名记进 meta, 同步进各路 attempt 目录
        dest = Path(ch.workdir) / "attachments" / "update_tpl.tar.gz"
        self.assertEqual(dest.read_bytes(), b"tarbytes")
        self.assertEqual(store.Challenge.load(ch.meta_path).defense_template,
                         "update_tpl.tar.gz")
        for a in ch.attempts:
            self.assertEqual((Path(a["workdir"]) / "attachments"
                              / "update_tpl.tar.gz").read_bytes(), b"tarbytes")


class VulnRelayTests(unittest.TestCase):
    """AWDP 漏洞点接力: 攻击路在 ## 漏洞点 区写下 [verified] 条目 ->
    monitor 按**条目数增长**触发 server._auto_defense_trigger
    (措辞改写/整理合并不重复推——实测同一漏洞改写措辞被重复推过三次);
    没有在跑的防御路就自动加开 (directive 带漏洞点原文),
    有就定向推消息排队, 不广播打扰攻击路。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        from core import monitor
        self.monitor = monitor

    def make_awdp(self, name="r1", **kw):
        opts = dict(category="pwn", harnesses=["codex"], awdp=True,
                    defense_harness="dsh")
        opts.update(kw)
        return store.create_challenge(self.root, name=name, **opts)

    @staticmethod
    def add_vuln_line(ch, line):
        board = Path(ch.workdir) / "board.md"
        text = board.read_text(encoding="utf-8")
        for l in text.splitlines():
            if l.startswith("## 漏洞点"):
                text = text.replace(l, l + "\n" + line, 1)
                break
        board.write_text(text, encoding="utf-8")

    @staticmethod
    def set_vuln_lines(ch, lines):
        """整体重写 ## 漏洞点 分区 (模拟 agent 改写措辞/整理合并)。"""
        import re
        board = Path(ch.workdir) / "board.md"
        text = board.read_text(encoding="utf-8")
        sec = re.search(r"^## 漏洞点[^\n]*\n.*?(?=^## |\Z)", text, re.S | re.M)
        head = re.search(r"^## 漏洞点[^\n]*\n", text, re.M).group(0)
        text = text[:sec.start()] + head + "\n".join(lines) + "\n\n" + text[sec.end():]
        board.write_text(text, encoding="utf-8")

    def test_auto_defense_default_skips_creation_time_defense(self):
        # 新默认: 创建 AWDP 题只开攻击路, 防御路等漏洞点接力
        ch = store.create_challenge(self.root, name="r0", category="pwn",
                                    harnesses=["codex"], awdp=True,
                                    defense_harnesses=["dsh"])
        self.assertEqual([(a["harness"], a["role"]) for a in ch.attempts],
                         [("codex", "attack")])

    def test_solo_awdp_attack_prompt_and_collab_files(self):
        # 单攻击路: 也有黑板/纪律文件 + 端口段指针 + 接力说明
        ch = self.make_awdp()
        self.assertTrue((Path(ch.workdir) / "AGENTS.md").is_file())
        self.assertTrue((Path(ch.workdir) / "board.md").is_file())
        text = server._attempt_prompt(ch, ch.attempts[0])
        self.assertIn("协作纪律", text)
        self.assertIn("30000-30999", text)
        self.assertIn("## 漏洞点", text)
        self.assertIn("[verified]", text)

    def test_poll_board_consumes_verified_vuln(self):
        ch = self.make_awdp()
        line = "- [verified] fmt 串溢出劫持 GOT（复现：%7$s 泄露 libc）"
        self.add_vuln_line(ch, line)
        self.add_vuln_line(ch, "- 猜测可能是栈溢出")   # 无 [verified] 不算
        m = self.monitor.Monitor({})
        self.assertTrue(m._poll_board(ch))
        self.assertEqual(ch.vuln_points, [line])
        self.assertEqual(ch.defense_feeds, [line])    # 已消费
        self.assertEqual(ch._defense_new, [line])     # 待触发
        ch._defense_new = None
        self.assertFalse(m._poll_board(ch))           # 无变化不重复触发
        self.assertFalse(getattr(ch, "_defense_new", None))

    def test_no_trigger_when_auto_defense_off(self):
        ch = self.make_awdp(name="r1b", auto_defense=False)
        self.add_vuln_line(ch, "- [verified] x（复现：y）")
        m = self.monitor.Monitor({})
        self.assertTrue(m._poll_board(ch))
        self.assertEqual(ch.vuln_points, ["- [verified] x（复现：y）"])  # 计数照更
        self.assertEqual(ch.defense_feeds, [])        # 但不消费不触发
        self.assertFalse(getattr(ch, "_defense_new", None))

    def test_drain_calls_handler_and_clears(self):
        import asyncio
        from unittest.mock import AsyncMock
        m = self.monitor.Monitor({})
        m.defense_handler = AsyncMock()
        m._defense_requests = [("cid1", ["- [verified] a"], ["- [verified] 旧基线"])]
        asyncio.run(m._drain_defense_requests())
        m.defense_handler.assert_awaited_once_with(
            "cid1", ["- [verified] a"], ["- [verified] 旧基线"])
        self.assertEqual(m._defense_requests, [])
        # handler 没注册也清空, 不跨轮积压
        m.defense_handler = None
        m._defense_requests = [("cid2", ["- [verified] b"], [])]
        asyncio.run(m._drain_defense_requests())
        self.assertEqual(m._defense_requests, [])

    def test_trigger_launches_defense_lane_with_directive(self):
        import asyncio
        from unittest.mock import AsyncMock
        ch = self.make_awdp()
        line = "- [verified] fmt 溢出（复现：…）"
        with patch.object(server.store, "find_challenge", return_value=ch), \
             patch.object(server.tmuxctl, "pane_exists", return_value=False), \
             patch.object(server, "_launch_attempt", new=AsyncMock()) as launch:
            asyncio.run(server._auto_defense_trigger(ch.id, [line]))
        att = ch.attempts[-1]
        self.assertEqual(att["role"], "defense")
        self.assertEqual(att["harness"], "dsh")       # 题目级 defense_harness
        self.assertIn(line, att["directive"])          # 直奔这个洞修
        self.assertIn("自动加开", att["note"])
        launch.assert_awaited_once()

    def test_trigger_messages_running_defense_lane(self):
        import asyncio
        ch = self.make_awdp(name="r2")
        att = store.add_attempt(ch, "dsh", role="defense")
        att["status"] = "running"
        att["tmux"] = {"session": "t", "pane": "%21"}
        ch.save()
        line = "- [verified] 第二个洞（复现：…）"
        with patch.object(server.store, "find_challenge", return_value=ch), \
             patch.object(server.tmuxctl, "pane_exists", return_value=True), \
             patch.object(server.tmuxctl, "send_text") as send:
            asyncio.run(server._auto_defense_trigger(ch.id, [line]))
        self.assertEqual(len(ch.attempts), 2)          # 不再开新一路
        pane, text = send.call_args[0]
        self.assertEqual(pane, "%21")
        self.assertIn(line, text)
        self.assertIn("排进修补队列", text)

    def test_seed_consumes_existing_vulns_without_trigger(self):
        # 重启播种: 板上已有漏洞点记为已消费, 不补触发 (要开防御路人工点加开)
        ch = self.make_awdp(name="r3")
        line = "- [verified] 重启前写下的洞（复现：…）"
        self.add_vuln_line(ch, line)
        ch2 = store.Challenge.load(ch.meta_path)
        with patch.object(self.monitor.store, "all_active_challenges",
                          return_value=[ch2]), \
             patch.object(self.monitor.store, "get_root", return_value=None):
            m = self.monitor.Monitor({})
            m.seed_deliverables()
        self.assertEqual(ch2.defense_feeds, [line])
        self.assertEqual(ch2.vuln_points, [line])
        self.assertEqual(m._defense_requests, [])

    def test_rewrite_same_count_does_not_retrigger(self):
        # 同一漏洞改写措辞 (条目数不变): 不重复推给防御路
        ch = self.make_awdp(name="r4")
        m = self.monitor.Monitor({})
        self.set_vuln_lines(ch, ["- [verified] nonce 复用（复现：两笔同 r）"])
        m._poll_board(ch)
        self.assertEqual(len(ch._defense_new), 1)      # 首次正常触发
        ch._defense_new = None
        self.set_vuln_lines(ch, ["- [verified] ECDSA 确定性 nonce 复用导致私钥泄露，"
                                 "措辞完全重写（复现：exp.py 输出）"])
        self.assertTrue(m._poll_board(ch))             # 板子变了
        self.assertFalse(getattr(ch, "_defense_new", None))   # 但不重复推
        self.assertEqual(len(ch.defense_feeds), 1)     # 基线不动

    def test_consolidation_shrink_only_rebaselines(self):
        # 整理合并 (条目数变少): 重新对齐基线, 不推
        ch = self.make_awdp(name="r4b")
        m = self.monitor.Monitor({})
        self.set_vuln_lines(ch, ["- [verified] 洞一（复现：a）",
                                 "- [verified] 洞二（复现：b）"])
        m._poll_board(ch)
        self.assertEqual(len(ch.defense_feeds), 2)
        ch._defense_new = None
        self.set_vuln_lines(ch, ["- [verified] 洞一洞二合并为一条（复现：ab）"])
        self.assertTrue(m._poll_board(ch))
        self.assertFalse(getattr(ch, "_defense_new", None))
        self.assertEqual(len(ch.defense_feeds), 1)     # 基线对齐到 1
        # 之后再新增能正常触发 (不会被旧基线吞掉; 先越过冷却期隔离干扰)
        ch.defense_last_trigger = 0
        self.set_vuln_lines(ch, ["- [verified] 洞一洞二合并为一条（复现：ab）",
                                 "- [verified] 新洞（复现：c）"])
        m._poll_board(ch)
        self.assertEqual(len(ch._defense_new), 2)

    def test_cooldown_batches_rapid_growth(self):
        ch = self.make_awdp(name="r5")
        m = self.monitor.Monitor({"defense_push_cooldown": 180})
        self.set_vuln_lines(ch, ["- [verified] 洞一（复现：a）"])
        m._poll_board(ch)
        self.assertEqual(len(ch._defense_new), 1)
        ch._defense_new = None
        first_ts = ch.defense_last_trigger
        self.assertGreater(first_ts, 0)
        self.set_vuln_lines(ch, ["- [verified] 洞一（复现：a）",
                                 "- [verified] 洞二（复现：b）"])
        m._poll_board(ch)                              # 冷却中: 不触发不消费
        self.assertFalse(getattr(ch, "_defense_new", None))
        self.assertEqual(len(ch.defense_feeds), 1)
        # 冷却到期: 板子没再变, 下一轮 poll 在 mtime 短路分支里补上触发, 推全量
        ch.defense_last_trigger = first_ts - 9999
        self.assertTrue(m._poll_board(ch))
        self.assertEqual(ch._defense_new, ["- [verified] 洞一（复现：a）",
                                           "- [verified] 洞二（复现：b）"])
        self.assertEqual(len(ch.defense_feeds), 2)


class JevGateTests(unittest.TestCase):
    """Jev (TypeSafe System One) 语义闸门: 漏洞点触发时逐条判"是不是基线之外
    的新洞", 纯改写/补充不推; Jev 不可用(没 key/超时/缺答案)一律回退 None,
    调用方按原有行为全推, 模型故障不卡死接力。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        from core import jevgate
        self.jevgate = jevgate

    def cfg(self, **kw):
        return {"jev_vuln_gate": True, "jev_vuln_threshold": 0.6, **kw}

    def mock_resp(self, nouls):
        from unittest.mock import MagicMock
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"answers": {
            f"v{i}": {"type": "noul", "noul": n} for i, n in enumerate(nouls)}}
        return resp

    def test_disabled_or_no_key_returns_none(self):
        self.assertIsNone(self.jevgate.filter_new_vulns({}, ["旧"], ["新"]))
        with patch.dict(os.environ, {"TYPESAFE_API_KEY": ""}):
            self.assertIsNone(
                self.jevgate.filter_new_vulns(self.cfg(), [], ["新"]))

    def test_filters_by_threshold_one_call(self):
        with patch.dict(os.environ, {"TYPESAFE_API_KEY": "k"}), \
             patch.object(self.jevgate.requests, "post",
                          return_value=self.mock_resp([0.97, 0.12])) as post:
            out = self.jevgate.filter_new_vulns(
                self.cfg(), ["基线旧洞"], ["新洞", "旧洞改写"])
        self.assertEqual(out, ["新洞"])
        # 一次调用并行判多条: state 带基线, 一候选一 noul 问题
        body = post.call_args.kwargs["json"]
        self.assertEqual(body["model"], "jev-latest")
        self.assertIn("基线旧洞", body["state"])
        self.assertIn("[0] 新洞", body["state"])
        self.assertEqual(set(body["questions"]), {"v0", "v1"})
        self.assertEqual(body["questions"]["v1"]["type"], "noul")

    def test_api_failure_and_missing_answer_fall_back(self):
        import requests as rq
        with patch.dict(os.environ, {"TYPESAFE_API_KEY": "k"}), \
             patch.object(self.jevgate.requests, "post",
                          side_effect=rq.ConnectionError):
            self.assertIsNone(self.jevgate.filter_new_vulns(self.cfg(), [], ["x"]))
        with patch.dict(os.environ, {"TYPESAFE_API_KEY": "k"}), \
             patch.object(self.jevgate.requests, "post",
                          return_value=self.mock_resp([])):   # 缺答案
            self.assertIsNone(self.jevgate.filter_new_vulns(self.cfg(), [], ["x"]))

    def test_handler_suppresses_when_jev_says_all_rewrites(self):
        import asyncio
        ch = store.create_challenge(self.root, name="j1", category="pwn",
                                    harnesses=["codex"], awdp=True,
                                    defense_harness="dsh")
        with patch.object(server.store, "find_challenge", return_value=ch), \
             patch.object(server.jevgate, "filter_new_vulns", return_value=[]), \
             patch.object(server.store, "add_attempt") as add:
            asyncio.run(server._auto_defense_trigger(
                ch.id, ["- [verified] 改写后的措辞"], ["- [verified] 原措辞"]))
        add.assert_not_called()            # 纯改写: 不开路不推消息

    def test_handler_falls_back_when_jev_down(self):
        import asyncio
        from unittest.mock import AsyncMock
        ch = store.create_challenge(self.root, name="j2", category="pwn",
                                    harnesses=["codex"], awdp=True,
                                    defense_harness="dsh")
        line = "- [verified] 新洞（复现：…）"
        with patch.object(server.store, "find_challenge", return_value=ch), \
             patch.object(server.jevgate, "filter_new_vulns", return_value=None), \
             patch.object(server.tmuxctl, "pane_exists", return_value=False), \
             patch.object(server, "_launch_attempt", new=AsyncMock()) as launch:
            asyncio.run(server._auto_defense_trigger(ch.id, [line], []))
        self.assertEqual(ch.attempts[-1]["role"], "defense")   # 回退全推
        self.assertIn(line, ch.attempts[-1]["directive"])
        launch.assert_awaited_once()


class HelpSpinGateTests(unittest.TestCase):
    """Jev 求助二审 + 空转检测 (monitor 层): 关键词/忙碌标志做免费预筛,
    Jev 只在候选事件上调用; 判定缓存/限流防重复调用; 不可用回退原行为。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        from core import monitor, jevgate
        self.monitor = monitor
        self.jevgate = jevgate

    def mk_monitor(self, **kw):
        cfg = {"help_keywords": ["需要人工", "帮我确认"],
               "jev_help_gate": True, "jev_spin_gate": True,
               "spin_check_interval": 300}
        cfg.update(kw)
        return self.monitor.Monitor(cfg)

    @staticmethod
    def jev_resp(noul):
        from unittest.mock import MagicMock
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"answers": {"q": {"type": "noul",
                                                    "noul": noul}}}
        return resp

    # ---- jevgate 层 ----

    def test_jevgate_thresholds_and_fallback(self):
        cfg = {"jev_help_gate": True, "jev_spin_gate": True}
        with patch.dict(os.environ, {"TYPESAFE_API_KEY": "k"}), \
             patch.object(self.jevgate.requests, "post",
                          return_value=self.jev_resp(0.65)):
            self.assertTrue(self.jevgate.judge_help(cfg, "…"))    # 0.65 >= 0.6
            self.assertFalse(self.jevgate.judge_spin(cfg, "…"))   # 0.65 < 0.7
        # 闸门关了 -> None; API 挂了 -> None
        self.assertIsNone(self.jevgate.judge_help({}, "…"))
        import requests as rq
        with patch.dict(os.environ, {"TYPESAFE_API_KEY": "k"}), \
             patch.object(self.jevgate.requests, "post",
                          side_effect=rq.Timeout):
            self.assertIsNone(self.jevgate.judge_spin(cfg, "…"))

    # ---- 求助二审 ----

    def test_help_keyword_hit_then_jev_second_opinion(self):
        m = self.mk_monitor()
        unit = {"workdir": self.root, "tmux": {}}
        text = "• 分析中\n• 需要人工确认远程地址\n"
        with patch.object(self.jevgate, "judge_help", return_value=False) as jh:
            self.assertFalse(m._agent_asking_help(text, unit))   # Jev 压掉误报
            self.assertFalse(m._agent_asking_help(text, unit))   # 缓存: 不再调
        self.assertEqual(jh.call_count, 1)

    def test_help_jev_down_falls_back_to_keyword(self):
        m = self.mk_monitor()
        unit = {"workdir": self.root, "tmux": {}}
        with patch.object(self.jevgate, "judge_help", return_value=None):
            self.assertTrue(m._agent_asking_help("• 需要人工介入\n", unit))

    def test_help_no_keyword_no_jev_call(self):
        m = self.mk_monitor()
        unit = {"workdir": self.root, "tmux": {}}
        with patch.object(self.jevgate, "judge_help") as jh:
            self.assertFalse(m._agent_asking_help("• 正常输出\n", unit))
        jh.assert_not_called()

    # ---- 空转检测 ----

    def make_ch_with_lane(self, name="sp1", role="attack"):
        ch = store.create_challenge(self.root, name=name, category="pwn",
                                    harnesses=["codex", "dsh"], awdp=True)
        unit = ch.attempts[0]
        unit["role"] = role
        unit["status"] = "running"
        unit["tmux"] = {"session": "t", "pane": "%31"}
        return ch, unit

    def test_spin_prefilters_are_free(self):
        m = self.mk_monitor()
        ch, unit = self.make_ch_with_lane()
        busy = "⠘ Working (12m) · esc to interrupt\n"
        with patch.object(self.jevgate, "judge_spin") as js:
            self.assertFalse(m._looks_spinning(ch, unit, "❯ idle\n"))  # 无忙碌标志
            ch.target = "1.2.3.4:1337"
            self.assertFalse(m._looks_spinning(ch, unit, busy))        # 远程已开
            ch.target = ""
            self.assertFalse(m._looks_spinning(ch, unit, busy))        # 未交付
        js.assert_not_called()

    def test_spin_detected_then_cached(self):
        m = self.mk_monitor()
        ch, unit = self.make_ch_with_lane()
        (Path(unit["workdir"]) / "flag.txt").write_text("flag{x}",
                                                        encoding="utf-8")
        busy = "⠘ Working (12m) · esc to interrupt\n"
        with patch.object(self.jevgate, "judge_spin", return_value=True) as js:
            self.assertTrue(m._looks_spinning(ch, unit, busy))
            unit["spin_suspected"] = True
            # 判定间隔内保持上次结论, 不重复调 API
            self.assertTrue(m._looks_spinning(ch, unit, busy))
        js.assert_called_once()

    def test_spin_jev_down_means_no_badge(self):
        m = self.mk_monitor()
        ch, unit = self.make_ch_with_lane()
        (Path(unit["workdir"]) / "flag.txt").write_text("flag{x}",
                                                        encoding="utf-8")
        with patch.object(self.jevgate, "judge_spin", return_value=None):
            self.assertFalse(m._looks_spinning(ch, unit,
                                               "esc to interrupt\n"))

    def test_spin_defense_lane_uses_deliverables(self):
        m = self.mk_monitor()
        ch, unit = self.make_ch_with_lane(name="sp2", role="defense")
        with patch.object(self.jevgate, "judge_spin", return_value=True) as js:
            self.assertFalse(m._looks_spinning(ch, unit,
                                               "esc to interrupt\n"))  # 无修补包
            ch.deliverables = [{"path": "x", "note": "y"}]
            self.assertTrue(m._looks_spinning(ch, unit,
                                              "esc to interrupt\n"))
        js.assert_called_once()

    def test_poll_unit_sets_and_clears_badge(self):
        m = self.mk_monitor()
        ch, unit = self.make_ch_with_lane(name="sp3")
        (Path(unit["workdir"]) / "flag.txt").write_text("flag{x}",
                                                        encoding="utf-8")
        with patch.object(self.monitor.tmuxctl, "pane_exists",
                          return_value=True), \
             patch.object(self.monitor.tmuxctl, "pane_current_command",
                          return_value="dsh"), \
             patch.object(self.monitor.tmuxctl, "capture",
                          return_value="⠘ Working · esc to interrupt\n"), \
             patch.object(self.jevgate, "judge_spin", return_value=True):
            m._poll_unit(ch, unit)
            self.assertTrue(unit["spin_suspected"])
        # 退回空闲输入框 (无忙碌标志) -> 徽章清掉, 也不再调 Jev
        with patch.object(self.monitor.tmuxctl, "pane_exists",
                          return_value=True), \
             patch.object(self.monitor.tmuxctl, "pane_current_command",
                          return_value="dsh"), \
             patch.object(self.monitor.tmuxctl, "capture",
                          return_value="❯ 空闲\n"), \
             patch.object(self.jevgate, "judge_spin") as js:
            m._poll_unit(ch, unit)
            self.assertFalse(unit["spin_suspected"])
        js.assert_not_called()


class DeleteAttemptTests(unittest.TestCase):
    """删除某一路: 杀 pane + 移出 attempts, 拒答/跑偏时删了重开。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_reallocation_after_delete_no_collision(self):
        ch = store.create_challenge(self.root, name="d1", category="misc",
                                    harnesses=["codex", "dsh", "claude"])
        store.remove_attempt(ch, "a1")
        self.assertEqual([a["id"] for a in ch.attempts], ["a0", "a2"])
        att = store.add_attempt(ch, "dsh")
        # 不复用被删的 a1, 也不撞还活着的 a2 (id 和端口段都按最大编号+1)
        self.assertEqual(att["id"], "a3")
        self.assertEqual(att["port_base"], 33000)
        self.assertEqual(store.Challenge.load(ch.meta_path).attempts[-1]["id"], "a3")

    def test_remove_attempt_clears_flag_attribution(self):
        ch = store.create_challenge(self.root, name="d2", category="misc",
                                    harnesses=["codex", "dsh"])
        ch.flag = "flag{x}"
        ch.flag_attempt = "a1"
        ch.save()
        store.remove_attempt(ch, "a1")
        self.assertEqual(ch.flag_attempt, "")        # 归属清掉
        self.assertEqual(ch.flag, "flag{x}")         # flag 本身保留

    def test_remove_unknown_attempt_raises(self):
        ch = store.create_challenge(self.root, name="d3", category="misc",
                                    harnesses=["codex", "dsh"])
        with self.assertRaises(ValueError):
            store.remove_attempt(ch, "a9")

    def test_delete_endpoint_kills_pane_and_removes(self):
        ch = store.create_challenge(self.root, name="d4", category="misc",
                                    harnesses=["codex", "dsh"])
        ch.attempts[1]["tmux"] = {"session": "t", "pane": "%11"}
        ch.save()
        with patch.object(server, "_get", return_value=ch), \
             patch.object(server.tmuxctl, "kill_pane") as kill:
            result = server.delete_attempt(ch.id, "a1")
        kill.assert_called_once_with("%11", session="t", ubz_id="")
        self.assertEqual([a["id"] for a in result["attempts"]], ["a0"])

    def test_delete_endpoint_guards(self):
        legacy = store.Challenge(id="d5", name="d5", category="misc",
                                 workdir=self.root, root=self.root)
        with patch.object(server, "_get", return_value=legacy):
            with self.assertRaises(Exception) as ctx:
                server.delete_attempt(legacy.id, "a0")
        self.assertIn("单路题", str(ctx.exception))

        solo = store.create_challenge(self.root, name="d6", category="misc",
                                      harnesses=["codex"])
        with patch.object(server, "_get", return_value=solo):
            with self.assertRaises(Exception) as ctx:
                server.delete_attempt(solo.id, "a0")
        self.assertIn("最后一路", str(ctx.exception))

        ch = store.create_challenge(self.root, name="d7", category="misc",
                                    harnesses=["codex", "dsh"])
        with patch.object(server, "_get", return_value=ch):
            with self.assertRaises(Exception) as ctx:
                server.delete_attempt(ch.id, "a9")
        self.assertIn("没有 attempt", str(ctx.exception))

    def test_delete_files_never_touches_main_dir(self):
        # 旧题转换: a0 住主目录
        ch = store.Challenge(id="d8", name="d8", category="misc",
                             workdir=str(Path(self.root) / "d8"), root=self.root,
                             tmux={"session": "t", "pane": "%9"}, status="running",
                             prompt_sent=True)
        Path(ch.workdir).mkdir(parents=True)
        ch.save()
        store.add_attempt(ch, "dsh")   # -> a1 在 runs/dsh
        with patch.object(server, "_get", return_value=ch), \
             patch.object(server.tmuxctl, "kill_pane"):
            server.delete_attempt(ch.id, "a1", files=True)
        self.assertFalse((Path(ch.workdir) / "runs" / "dsh").exists())
        # 删 a0 (旧题转换住主目录的那路): files=true 也不能动主目录
        store.add_attempt(ch, "codex")   # 先补回两路, 绕过"最后一路"护栏
        with patch.object(server, "_get", return_value=ch), \
             patch.object(server.tmuxctl, "kill_pane"):
            server.delete_attempt(ch.id, "a0", files=True)
        self.assertTrue(Path(ch.workdir).is_dir())
        self.assertTrue((Path(ch.workdir) / "meta.json").is_file())


class BoardSkeletonTests(unittest.TestCase):
    """黑板骨架: Inbox 兜底区必须在最后 (agent/人随手 >> 追加到文件尾是改不掉的习惯,
    殿后分区是什么, EOF 追加就进什么——Flags 殿后时被污染过)。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_inbox_is_last_section(self):
        sections = [l for l in store.BOARD_MD.splitlines() if l.startswith("## ")]
        names = [l.split("（")[0] for l in sections]
        self.assertEqual(names[-1], "## Inbox")
        self.assertIn("## Flags", names)
        self.assertIn("## 补丁包", names)
        self.assertLess(names.index("## Flags"), len(names) - 1)
        self.assertLess(names.index("## 补丁包"), len(names) - 1)

    def test_vuln_section_right_after_facts(self):
        # 漏洞点接力解析只认这个分区; 位置紧随 Facts (攻击路写事实时顺手写漏洞点)
        sections = [l for l in store.BOARD_MD.splitlines() if l.startswith("## ")]
        names = [l.split("（")[0] for l in sections]
        self.assertEqual(names[:3], ["## Facts", "## 漏洞点", "## Dead-ends"])

    def test_old_board_upgraded_in_place(self):
        # 存量老板子没有 ## 漏洞点: 补插到 Dead-ends 之前, 幂等
        ch = store.create_challenge(self.root, name="b2", category="misc",
                                    harnesses=["codex", "dsh"])
        board = Path(ch.workdir) / "board.md"
        old = "# b\n## Facts\n\n- [verified] 老条目\n\n## Dead-ends\n\n## Inbox\n"
        board.write_text(old, encoding="utf-8")
        self.assertTrue(store.upgrade_board_sections(ch))
        text = board.read_text(encoding="utf-8")
        self.assertIn("## 漏洞点", text)
        self.assertLess(text.index("## Facts"), text.index("## 漏洞点"))
        self.assertLess(text.index("## 漏洞点"), text.index("## Dead-ends"))
        self.assertIn("老条目", text)                      # 存量内容不动
        self.assertFalse(store.upgrade_board_sections(ch))  # 幂等

    def test_agents_md_warns_against_eof_append(self):
        self.assertIn(">>", store.AGENTS_MD)
        self.assertIn("Inbox", store.AGENTS_MD)

    def test_new_multi_board_has_inbox(self):
        ch = store.create_challenge(self.root, name="b1", category="misc",
                                    harnesses=["codex", "dsh"])
        text = (Path(ch.workdir) / "board.md").read_text(encoding="utf-8")
        self.assertTrue(text.rstrip().endswith(
            "## Inbox（速记/来不及分类的放这里，之后任何人归档到上面分区）"))


class DeliverableParseTests(unittest.TestCase):
    """卡片上的可用修补包: monitor 只解析黑板「补丁包」分区里提到
    update.tar.gz 且文件真实存在的条目行。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        from core import monitor
        self.monitor = monitor
        self.mon = monitor.Monitor({})

    def make(self, name="p1"):
        ch = store.create_challenge(self.root, name=name, category="pwn",
                                    harnesses=["codex", "dsh"], awdp=True)
        return ch

    def add_pkg_line(self, ch, line):
        """把条目写进补丁包分区标题下 (和纪律文件要求 agent 的写法一致)。"""
        board = Path(ch.workdir) / "board.md"
        text = board.read_text(encoding="utf-8")
        for l in text.splitlines():
            if l.startswith("## 补丁包"):
                text = text.replace(l, l + "\n" + line, 1)
                break
        board.write_text(text, encoding="utf-8")

    def test_deliverable_parsed_when_file_exists(self):
        ch = self.make()
        pkg = Path(ch.workdir) / "runs" / "dsh" / "update.tar.gz"
        pkg.write_bytes(b"tar")
        self.add_pkg_line(ch, "- 修补包 runs/dsh/update.tar.gz（修了栈溢出+fmt）")
        self.assertTrue(self.monitor.Monitor({})._poll_board(ch))
        self.assertEqual(len(ch.deliverables), 1)
        self.assertEqual(ch.deliverables[0]["path"], "runs/dsh/update.tar.gz")
        self.assertIn("栈溢出", ch.deliverables[0]["note"])

    def test_mention_without_file_is_not_usable(self):
        ch = self.make("p2")
        self.add_pkg_line(ch, "- 打算把补丁打成 runs/dsh/update.tar.gz")
        self.assertTrue(self.monitor.Monitor({})._poll_board(ch))
        self.assertEqual(ch.deliverables, [])        # 文件不存在, 不算可用

    def test_other_sections_ignored(self):
        ch = self.make("p2b")
        pkg = Path(ch.workdir) / "runs" / "dsh" / "update.tar.gz"
        pkg.write_bytes(b"tar")
        board = Path(ch.workdir) / "board.md"
        board.write_text(board.read_text(encoding="utf-8").replace(
            "## Facts（已验证的事实）",
            "## Facts（已验证的事实）\n- 修复包 runs/dsh/update.tar.gz 的结构"),
            encoding="utf-8")
        self.assertTrue(self.monitor.Monitor({})._poll_board(ch))
        self.assertEqual(ch.deliverables, [])        # 只认补丁包分区

    def test_absolute_path_and_backticks(self):
        ch = self.make("p3")
        pkg = Path(ch.workdir) / "runs" / "dsh" / "update.tar.gz"
        pkg.write_bytes(b"tar")
        self.add_pkg_line(ch, f"- 修补包 `{pkg}` 已打好")
        self.assertTrue(self.monitor.Monitor({})._poll_board(ch))
        self.assertEqual(ch.deliverables[0]["path"], str(pkg))   # 绝对路径也认

    def test_meta_roundtrip(self):
        ch = self.make("p4")
        ch.deliverables = [{"path": "runs/dsh/update.tar.gz", "note": "x"}]
        ch.save()
        self.assertEqual(store.Challenge.load(ch.meta_path).deliverables,
                         [{"path": "runs/dsh/update.tar.gz", "note": "x"}])

    def test_seed_picks_up_preexisting_board(self):
        # 老板子: board_updated 已是当前 mtime, _poll_board 短路不读;
        # 启动播种强制解析一次
        ch = self.make("p5")
        pkg = Path(ch.workdir) / "runs" / "dsh" / "update.tar.gz"
        pkg.write_bytes(b"tar")
        self.add_pkg_line(ch, "- 修补包 runs/dsh/update.tar.gz 已打好")
        self.monitor.Monitor({})._poll_board(ch)          # 先正常轮询一轮记下 mtime
        ch.save()
        ch2 = store.Challenge.load(ch.meta_path)      # 模拟重启后读回
        ch2.deliverables = []                          # 旧 meta 没有该字段
        with patch.object(self.monitor.store, "all_active_challenges",
                          return_value=[ch2]), \
             patch.object(self.monitor.store, "get_root", return_value=None):
            self.monitor.Monitor({}).seed_deliverables()
        self.assertEqual(ch2.deliverables[0]["path"], "runs/dsh/update.tar.gz")

    def test_deliverable_name_follows_template(self):
        # 包名以上传的交付模板为准: 模板叫别的名, 提示词和黑板解析都跟着走
        ch = store.create_challenge(self.root, name="p6", category="pwn", awdp=True,
                                    auto_defense=False,
                                    harnesses=["codex"], defense_harnesses=["dsh"])
        ch.defense_template = "patch_v2.tar.gz"
        pkg = Path(ch.workdir) / "runs" / "dsh" / "patch_v2.tar.gz"
        pkg.write_bytes(b"tar")
        self.add_pkg_line(ch, "- 修补包 runs/dsh/patch_v2.tar.gz 已打好")
        self.assertTrue(self.monitor.Monitor({})._poll_board(ch))
        self.assertEqual(ch.deliverables[0]["path"], "runs/dsh/patch_v2.tar.gz")
        # 提示词里的交付名也换成模板名
        import server as srv
        text = srv._attempt_prompt(ch, ch.attempts[1])
        self.assertIn("patch_v2.tar.gz", text)
        self.assertNotIn("打成 update.tar.gz", text)
        # 而板上提旧名字的不认
        self.add_pkg_line(ch, "- 修补包 runs/dsh/update.tar.gz 旧记录")
        (Path(ch.workdir) / "runs" / "dsh" / "update.tar.gz").write_bytes(b"old")
        self.monitor.Monitor({})._poll_board(ch)
        self.assertEqual([d["path"] for d in ch.deliverables],
                         ["runs/dsh/patch_v2.tar.gz"])


class ConcurrencyAndPaneSafetyTests(unittest.TestCase):
    """针对实测踩坑的回归保护:
    1) tmux 重启后 pane_id (%0/%1) 在其他 session 复用时, pane_exists 校验 session 防串台
    2) monitor 轮询或慢启动 harness 落盘时, 不冲掉并发 PATCH 保存的 target/supplements/flag
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def test_pane_exists_checks_session_when_provided(self):
        from core import tmuxctl
        with patch.object(tmuxctl, "_run", return_value=(
                "%0\tmain\t0\tzsh\t/tmp\t\n"
                "%1\tctf-2026wqbfinal2\t1\tcodex\t/tmp\tidentity-1\n")):
            self.assertTrue(tmuxctl.pane_exists("%1", "ctf-2026wqbfinal2"))
            self.assertFalse(tmuxctl.pane_exists("%0", "ctf-ubztest"))
            self.assertTrue(tmuxctl.pane_exists("%0"))  # 不传 session 维持兼容
            self.assertTrue(tmuxctl.pane_exists(
                "%1", "ctf-2026wqbfinal2", "identity-1"))
            self.assertFalse(tmuxctl.pane_exists(
                "%1", "ctf-2026wqbfinal2", "reused-by-other-harness"))

    def test_monitor_poll_does_not_clobber_concurrent_target_or_flag(self):
        from core import monitor
        ch = store.create_challenge(self.root, name="race1", category="pwn",
                                    harnesses=["cursor", "dsh"])
        ch.attempts[0]["status"] = "running"
        ch.attempts[0]["tmux"] = {"session": "ctf-x", "pane": "%10"}
        ch.save()

        # 模拟 monitor 已把旧 ch 读进内存, 期间用户通过 PATCH 补了 target 和 flag
        stale_ch = store.Challenge.load(ch.meta_path)
        fresh_on_disk = store.Challenge.load(ch.meta_path)
        fresh_on_disk.target = "123.56.12.16:20582"
        fresh_on_disk.supplements = [{"ts": 1.0, "text": "【环境补充】"}]
        fresh_on_disk.flag = "flag{real}"
        fresh_on_disk.status = "solved"
        fresh_on_disk.save()

        m = monitor.Monitor({})
        with patch.object(monitor.tmuxctl, "pane_exists", return_value=True), \
             patch.object(monitor.tmuxctl, "pane_current_command", return_value="cursor"), \
             patch.object(monitor.tmuxctl, "capture", return_value="new output line\n"):
            m._poll_challenge(stale_ch)

        after = store.Challenge.load(ch.meta_path)
        self.assertEqual(after.target, "123.56.12.16:20582")
        self.assertEqual(len(after.supplements), 1)
        self.assertEqual(after.flag, "flag{real}")
        self.assertEqual(after.status, "solved")
        # 终端正文不再持久化；meta 只保存运行状态和协作信息。
        self.assertEqual(after.attempts[0]["last_output"], "")

    def test_slow_launch_save_does_not_clobber_concurrent_target(self):
        ch = store.create_challenge(self.root, name="race2", category="pwn",
                                    harnesses=["cursor", "dsh"])
        # 模拟 dsh 慢启动 75s 期间用户已在磁盘上更新了 target
        disk_ch = store.Challenge.load(ch.meta_path)
        disk_ch.target = "101.200.57.204:22570"
        disk_ch.save()

        att = ch.attempts[1]
        att["status"] = "running"
        att["prompt_sent"] = True
        att["tmux"] = {"session": "ctf-x", "window": "0", "pane": "%12"}
        server._save_unit_state(ch, att)

        after = store.Challenge.load(ch.meta_path)
        self.assertEqual(after.target, "101.200.57.204:22570")
        self.assertEqual(after.attempts[1]["status"], "running")
        self.assertEqual(after.attempts[1]["tmux"]["pane"], "%12")

    def test_nested_zip_extracted_recursively(self):
        import io
        import zipfile
        from core import downloader, prompts

        ch = store.create_challenge(self.root, name="nested", category="pwn",
                                    harnesses=["codex"])
        attach_dir = Path(ch.workdir) / "attachments"

        # 构造内层 fmtnote.zip (含 pwn 与 libc.so.6)
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as zf:
            zf.writestr("pwn", b"\x7fELF-binary")
            zf.writestr("libc.so.6", b"\x7fELF-libc")
        # 构造外层套娃包 outer.zip -> tempdir/PWN附件/fmtnote.zip
        outer_path = attach_dir / "outer.zip"
        with zipfile.ZipFile(outer_path, "w") as zf:
            zf.writestr("tempdir/PWN附件/fmtnote.zip", inner_buf.getvalue())

        err = downloader._extract(outer_path, attach_dir, [])
        self.assertIsNone(err)
        self.assertTrue((attach_dir / "tempdir" / "PWN附件" / "pwn").is_file())
        self.assertTrue((attach_dir / "tempdir" / "PWN附件" / "libc.so.6").is_file())
        listing = prompts.attachments_listing(ch.workdir)
        self.assertIn("attachments/", listing)
        self.assertIn("find attachments", listing)
        self.assertIn("tree -a", listing)
        self.assertNotIn("libc.so.6", listing)   # 不再把完整文件名列表注入提示词
        self.assertNotIn("outer.zip", listing)

    def test_patch_target_resumes_exited_attack_lane(self):
        import asyncio
        from unittest.mock import AsyncMock

        ch = store.create_challenge(self.root, name="t_wake", category="pwn",
                                    harnesses=["cursor", "dsh"])
        ch.attempts[0]["status"] = "exited"
        ch.attempts[0]["prompt_sent"] = True
        ch.attempts[0]["tmux"] = {"session": "ctf-x", "pane": "%10"}
        ch.attempts[1]["status"] = "running"
        ch.attempts[1]["prompt_sent"] = True
        ch.attempts[1]["tmux"] = {"session": "ctf-x", "pane": "%11"}
        ch.save()

        with patch.object(server, "_get", return_value=ch), \
             patch.object(server, "_message_units", return_value=[ch.attempts[1]]), \
             patch.object(server.tmuxctl, "send_text") as send_text, \
             patch.object(server, "_resume_unit", new=AsyncMock()) as resume_unit:
            asyncio.run(server.patch_challenge(
                ch.id,
                server.PatchIn(target="123.57.42.96:22572",
                               message="【环境补充】新靶机已开放")))

        send_text.assert_called_once_with("%11", "【环境补充】新靶机已开放")
        resume_unit.assert_awaited_once()
        self.assertEqual(resume_unit.call_args.args[1]["id"], "a0")
        self.assertEqual(resume_unit.call_args.kwargs["custom_nudge"],
                         "【环境补充】新靶机已开放")

    def test_get_challenge_files_prioritizes_flag_writeup_and_exp(self):
        ch = store.create_challenge(self.root, name="fview", category="pwn",
                                    harnesses=["dsh"])
        wd = Path(ch.attempts[0]["workdir"])
        (wd / "notes.txt").write_text("some notes", encoding="utf-8")
        (wd / "writeup.md").write_text("# Writeup", encoding="utf-8")
        (wd / "flag.txt").write_text("flag{test_123}", encoding="utf-8")
        (wd / "work").mkdir()
        (wd / "work" / "exp.py").write_text("print('pwn')", encoding="utf-8")

        with patch.object(server, "_get", return_value=ch):
            res = server.get_challenge_files(ch.id, aid="a0")
        names = [f["name"] for f in res["files"]]
        self.assertEqual(names[:3], ["flag.txt", "writeup.md", "work/exp.py"])
        self.assertEqual(res["files"][0]["content"], "flag{test_123}")

    def test_harness_config_includes_kimi_and_agy(self):
        from core import harness
        cfg = store.load_config()
        names = harness.harness_names(cfg)
        for expected in ("codex", "claude", "cursor", "dsh", "kimi", "agy"):
            self.assertIn(expected, names)
        self.assertIn("--auto", harness.launch_command(cfg, "kimi"))
        self.assertIn("--continue", harness.resume_command(cfg, "kimi"))
        self.assertIn("GEMINI_API_KEY=magpie-agy", harness.launch_command(cfg, "agy"))
        self.assertIn("magpie/antigravity/gemini-4-argon", harness.launch_command(cfg, "agy"))
        self.assertIn("--continue", harness.resume_command(cfg, "agy"))

    def test_is_busy_and_idle_prompt_across_six_harnesses(self):
        from core import harness, tmuxctl

        # 忙碌态识别: 覆盖 6 个 harness
        self.assertTrue(tmuxctl.is_busy(["• Working (3s • esc to interrupt)"]))
        self.assertTrue(tmuxctl.is_busy(["* Undulating… "]))
        self.assertFalse(tmuxctl.is_busy(["✻ Sautéed for 12s · done 2:17 PM"]))
        self.assertFalse(tmuxctl.is_busy(["  * 思考 · 1s （ctrl+o 展开）"]))
        self.assertTrue(tmuxctl.is_busy(["  → Add a follow-up   ctrl+c to stop"]))
        self.assertTrue(tmuxctl.is_busy(["   esc 中断"]))
        self.assertTrue(tmuxctl.is_busy(["  🌑 · Tip: /tasks to check progress"]))
        self.assertTrue(tmuxctl.is_busy(["esc to cancel   accept-edits · gemini"]))
        self.assertTrue(tmuxctl.is_busy([" ■⬝⬝⬝⬝⬝⬝⬝ esc interrupt            shift+tab agents  ctrl+p commands"]))

        # 空闲输入框识别: 覆盖 dsh 0.16 ⌸ ❯ / kimi │ > / agy > / opencode ┃
        self.assertTrue(harness._has_idle_prompt(["  ⌸ ❯                                ⛶"]))
        self.assertTrue(harness._has_idle_prompt([" │ >                                 │"]))
        self.assertTrue(harness._has_idle_prompt(["> Accept-edits mode"]))
        self.assertTrue(harness._has_idle_prompt(["  ┃  Ask anything… \"Fix broken tests\""]))
        self.assertTrue(harness._has_idle_prompt(["  ┃"]))

        # 排除 dsh 启动未就绪态与 kimi/agy 信任弹窗选项
        self.assertFalse(harness._has_idle_prompt([
            "  ⌸ ❯                                ⛶",
            "   正在启动 DSH… · deepseek-flash",
        ]))
        self.assertFalse(harness._has_idle_prompt([
            "  Trust this folder?",
            "   ❯ Trust and continue",
        ]))
        self.assertFalse(harness._has_idle_prompt([
            "Do you trust the contents of this project?",
            "> Yes, I trust this folder",
        ]))
        self.assertFalse(harness._has_idle_prompt([
            " Is this a project you created or one you trust?",
            " ❯ No, exit",
            "   Yes, I trust this folder",
        ]))

    def test_claude_trust_dialog_and_slow_shell_startup(self):
        from core import harness, tmuxctl

        # 模拟专属附件踩坑现场:
        # 前两帧 shell 还在跑 .zshrc / jq wrapper (尾行仍是 echo UBZ-EXIT:$?),
        # 第 3 帧才弹出 Claude 信任弹窗 (默认光标在 ❯ No, exit),
        # 按 Down+Enter 后第 4/5 帧进入真正的 ❯ 输入框。
        frames = [
            ["$ claude --dangerously-skip-permissions ; echo UBZ-EXIT:$?"],
            ["$ claude --dangerously-skip-permissions ; echo UBZ-EXIT:$?"],
            [
                " Workspace:",
                " /home/ef4tless/ctf/ubztest/chall/runs/claude",
                " Is this a project you created or one you trust?",
                " ❯ No, exit",
                "   Yes, I trust this folder",
            ],
            ["❯ ", "  ⏵⏵ bypass permissions on"],
            ["❯ ", "  ⏵⏵ bypass permissions on"],
        ]
        idx = {"i": 0}

        def fake_tail(_pane, _n=12):
            cur = frames[min(idx["i"], len(frames) - 1)]
            idx["i"] += 1
            return cur

        with patch.object(tmuxctl, "_visible_tail", side_effect=fake_tail), \
             patch.object(tmuxctl, "_run") as run_mock, \
             patch.object(tmuxctl.time, "sleep"):
            tmuxctl._dismiss_dialogs("%17", timeout=8.0)

        # 必须等到第 3 帧弹窗出现并发送 Down + Enter, 绝不能在前两帧提前 clean 退出
        sent_keys = [c.args[0][-1] for c in run_mock.call_args_list
                     if c.args and c.args[0][0] == "send-keys"]
        self.assertEqual(sent_keys, ["Down", "Enter"])
        self.assertGreaterEqual(idx["i"], 5)

    def test_claude_trust_dialog_with_question_above_visible_tail(self):
        from core import tmuxctl

        frames = [
            [" ❯ No, exit", "   Yes, I trust this folder",
             " Enter to confirm · Esc to cancel"],
            ["❯ ", "  ⏵⏵ bypass permissions on"],
            ["❯ ", "  ⏵⏵ bypass permissions on"],
        ]
        idx = {"i": 0}

        def fake_tail(_pane, _n=14):
            cur = frames[min(idx["i"], len(frames) - 1)]
            idx["i"] += 1
            return cur

        with patch.object(tmuxctl, "_visible_tail", side_effect=fake_tail), \
             patch.object(tmuxctl, "_run") as run_mock, \
             patch.object(tmuxctl.time, "sleep"):
            tmuxctl._dismiss_dialogs("%23", timeout=8.0)

        sent_keys = [c.args[0][-1] for c in run_mock.call_args_list
                     if c.args and c.args[0][0] == "send-keys"]
        self.assertEqual(sent_keys, ["Down", "Enter"])

    def test_append_board_entry_atomic_and_dedup(self):
        board = Path(self.root) / "board.md"
        self.assertTrue(store.append_board_entry(
            board, "fact", "tboxgw 为静态 musl 非 PIE", source="dsh"))
        # 同一条事实重复写 (哪怕换了来源) 自动去重跳过
        self.assertFalse(store.append_board_entry(
            board, "fact", "tboxgw 为静态 musl 非 PIE", source="cursor"))
        self.assertTrue(store.append_board_entry(
            board, "vuln", "sub_401485 memcpy 栈溢出", source="dsh"))
        self.assertTrue(store.append_board_entry(
            board, "dead", "内置无 flag 字符串 — 已否证", source="claude"))

        text = board.read_text(encoding="utf-8")
        # 严格落在各自分区标题之下, 绝不串进 ## Flags
        self.assertLess(text.index("tboxgw 为静态 musl 非 PIE"), text.index("## 漏洞点"))
        self.assertLess(text.index("sub_401485 memcpy 栈溢出"), text.index("## Dead-ends"))
        self.assertLess(text.index("内置无 flag 字符串"), text.index("## 占用声明"))

    def test_parse_vuln_points_flexible_and_facts_fallback(self):
        from core import monitor
        # 1) ## 漏洞点 内带 [dsh 09:45] 前缀或粗体 **[verified]** 都能识别
        md1 = (
            "## Facts\n\n"
            "## 漏洞点\n"
            "- [dsh 09:45] [verified] 栈溢出 @ sub_401485\n"
            "- **[verified]** 格式化字符串 @ sub_401600\n"
            "- 猜测可能还有一处溢出\n"
            "## Dead-ends\n"
        )
        vulns1 = monitor.Monitor._parse_vuln_points(md1)
        self.assertEqual(len(vulns1), 2)

        # 2) ## 漏洞点 为空时, 兜底识别写在 ## Facts 里的 [verified] 漏洞条目
        md2 = (
            "## Facts\n"
            "- [verified] 附件为 64-bit PIE ELF\n"
            "- [verified] **漏洞根因**：sub_401485 中 cnt 无校验导致 memcpy 栈溢出\n"
            "## 漏洞点\n\n"
            "## Dead-ends\n"
        )
        vulns2 = monitor.Monitor._parse_vuln_points(md2)
        self.assertEqual(len(vulns2), 1)
        self.assertIn("sub_401485", vulns2[0])

    def test_put_board_edit_and_notify(self):
        ch = store.create_challenge(self.root, name="bedit", category="pwn",
                                    harnesses=["claude", "dsh"])
        ch.attempts[0]["status"] = "running"
        ch.attempts[0]["tmux"] = {"session": "ctf-x", "pane": "%21"}
        ch.save()

        with patch.object(server, "_get", return_value=ch), \
             patch.object(server, "_message_units", return_value=[ch.attempts[0]]), \
             patch.object(server.tmuxctl, "send_text") as send_text:
            res = server.put_board(
                ch.id,
                server.BoardUpdateIn(
                    section="dead",
                    entry="不要爆破 38 字节输入，走逆 Feistel",
                    notify=True,
                ),
            )
        self.assertEqual(res["entries"], 1)
        self.assertEqual(res["notified"], 1)
        self.assertIn("不要爆破 38 字节输入", res["content"])
        send_text.assert_called_once()
        self.assertEqual(send_text.call_args.args[0], "%21")
        self.assertIn("board.md", send_text.call_args.args[1])

    def test_idle_at_prompt_detection_and_readonly_collab_rule(self):
        from core import monitor
        # 纪律文件包含跨目录只读复用与禁止直接写队友目录的规范
        self.assertIn("只读查看或拷贝复用，严禁跨目录直接写", store.AGENTS_MD)
        self.assertIn("../<队友harness>/", store.AGENTS_MD)

        ch = store.create_challenge(self.root, name="idle_chk", category="misc",
                                    harnesses=["dsh", "kimi"])
        u0 = ch.attempts[0]
        u0["status"] = "running"
        u0["tmux"] = {"session": "ctf-x", "pane": "%18"}
        m = monitor.Monitor({})

        # 1) 正在忙碌执行 (esc 中断) -> idle_at_prompt 为 False
        with patch.object(monitor.tmuxctl, "pane_exists", return_value=True), \
             patch.object(monitor.tmuxctl, "pane_current_command", return_value="dsh-tui"), \
             patch.object(monitor.tmuxctl, "capture",
                          return_value="  ⌸ ❯ \n   esc 中断 · deepseek-chat\n"):
            m._poll_unit(ch, u0)
        self.assertFalse(u0.get("idle_at_prompt"))

        # 2) 执行完毕停在空闲输入框 (无忙碌标志) -> idle_at_prompt 为 True
        with patch.object(monitor.tmuxctl, "pane_exists", return_value=True), \
             patch.object(monitor.tmuxctl, "pane_current_command", return_value="dsh-tui"), \
             patch.object(monitor.tmuxctl, "capture",
                          return_value="  ⌸ ❯                                ⛶\n   就绪 · deepseek-chat\n"):
            m._poll_unit(ch, u0)
        self.assertTrue(u0.get("idle_at_prompt"))

    def test_launch_saves_pane_early_and_nonblocking_endpoint(self):
        import asyncio
        ch = store.create_challenge(self.root, name="fast_l", category="misc",
                                    harnesses=["dsh"])
        att = ch.attempts[0]
        seen_pane_during_wait = []

        def fake_wait_ready(pane, hname):
            # 在 wait_ready 阻塞期间, meta.json 里必须已经落盘了分配好的 pane_id
            disk = store.Challenge.load(ch.meta_path)
            seen_pane_during_wait.append(disk.attempts[0]["tmux"].get("pane"))
            return True

        with patch.object(server.tmuxctl, "allocate_pane",
                          return_value={"session": "ctf-x", "window": "1", "pane": "%77"}), \
             patch.object(server.tmuxctl, "send_command"), \
             patch.object(server.tmuxctl, "launch_harness"), \
             patch.object(server.harness, "wait_ready", side_effect=fake_wait_ready), \
             patch.object(server.tmuxctl, "send_text"):
            asyncio.run(server._launch_attempt(ch, att))

        self.assertEqual(seen_pane_during_wait, ["%77"])
        after = store.Challenge.load(ch.meta_path)
        self.assertEqual(after.attempts[0]["status"], "running")
        self.assertEqual(after.attempts[0]["tmux"]["pane"], "%77")
