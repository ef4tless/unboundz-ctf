import tempfile
import unittest
from unittest.mock import patch

import server
from core import contest, store

# 按《AI智能体解题赛接口文档.pdf》示例构造的适配器与响应
ADAPTER = {
    "id": "mock-ai",
    "name": "模拟赛",
    "apis": {
        "list": {
            "method": "GET",
            "url": "https://x.test/list?token={token}",
            "ok": "code == 0",
            "data": "data",
            "fields": {
                "question_id": "question_id",
                "title": "title",
                "category": "category",
                "score": "score",
                "description": "description",
                "file_url": "file_url",
                "is_solved": "is_solved",
                "solved_number": "solved_number",
                "interactive": "interactive",
                "attributes": "attributes",
                "capabilities": "capabilities",
                "connection": "connection",
            },
            "target_fields": ["connection.docker_url"],
        },
        "reset": {
            "method": "GET",
            "url": "https://x.test/reset?token={token}&question_id={question_id}",
            "ok": "code == 0",
        },
        "submit": {
            "method": "GET",
            "url": "https://x.test/submit?token={token}&question_id={question_id}&answer={answer}",
            # 与 contests/wanwubei-ai.yaml 实测一致的判定式
            "ok": 'code == 0 and (status == 1 or "正确" in str(message)) and "不正确" not in str(message) and "错误" not in str(message)',
        },
    },
    "category_map": {"reverse": "re"},
}

LIST_RESP = {
    "code": 0,
    "message": "查询成功",
    "data": [
        {
            "question_id": "Q1",
            "title": "测试_附件",
            "score": 100,
            "real_score": 100,
            "file_url": "https://x.test/a.zip",
            "is_solved": False,
            "solved_number": 0,
            "category": "misc",
            "attributes": ["标签", "杂项"],
            "description": "测试_多附件题目",
            "interactive": "false",
            "capabilities": ["能力"],
            "connection": [],
            "extensions": {"aaa": "x"},
        },
        {
            "question_id": "Q2",
            "title": "sign_shellcode",
            "score": 500,
            "real_score": 500,
            "file_url": "",
            "is_solved": False,
            "solved_number": 0,
            "category": "Reverse",
            "attributes": ["docker"],
            "description": "test",
            "interactive": "true",
            "capabilities": ["docker"],
            "connection": {"docker_url": "nc 1.2.3.4 2333", "docker_ip": "1.2.3.4", "docker_port": "2333"},
            "extensions": {},
        },
    ],
}


class RenderEvalTests(unittest.TestCase):
    def test_url_template_encodes_values(self):
        out = contest._render("https://x/?a={answer}&t={token}", {"answer": "flag{a b&c}", "token": "tok"}, encode=True)
        self.assertEqual(out, "https://x/?a=flag%7Ba%20b%26c%7D&t=tok")

    def test_dig_nested_and_list_index(self):
        obj = {"a": {"b": [{"c": 1}]}}
        self.assertEqual(contest.dig(obj, "a.b.0.c"), 1)
        self.assertIsNone(contest.dig(obj, "a.x.y"))
        self.assertIsNone(contest.dig(obj, "a.b.9.c"))

    def test_check_ok(self):
        self.assertTrue(contest.check_ok("code == 0 and status == 1", {"code": 0, "status": 1}))
        self.assertFalse(contest.check_ok("code == 0 and status == 1", {"code": 0, "status": 0}))
        # 键缺失按 None 处理而不是抛错
        self.assertFalse(contest.check_ok("code == 0 and status == 1", {"code": 0}))
        self.assertTrue(contest.check_ok("", {"anything": 1}))


class QuestionFlowTests(unittest.TestCase):
    def test_fetch_questions_normalizes_pdf_shape(self):
        with patch.object(contest, "_request", return_value=LIST_RESP):
            qs = contest.fetch_questions(ADAPTER, "tok")
        self.assertEqual(len(qs), 2)
        misc, pwn = qs
        self.assertEqual(misc["question_id"], "Q1")
        self.assertEqual(misc["category"], "misc")
        self.assertFalse(misc["interactive"])      # 字符串 "false" -> False
        self.assertEqual(misc["file_url"], "https://x.test/a.zip")
        self.assertEqual(pwn["category"], "re")    # category_map: Reverse -> re
        self.assertEqual(pwn["category_raw"], "Reverse")
        self.assertTrue(pwn["interactive"])        # 字符串 "true" -> True
        self.assertEqual(pwn["target"], "nc 1.2.3.4 2333")

    def test_fetch_questions_platform_error(self):
        with patch.object(contest, "_request", return_value={"code": 1, "message": "token 无效"}):
            with self.assertRaises(contest.ContestError):
                contest.fetch_questions(ADAPTER, "bad")

    def test_submit_answer_ok_flag(self):
        # 首次答对(实测 2026-09-10): 没有 status 字段, 只有 message
        with patch.object(contest, "_request", return_value={"code": 0, "message": "恭喜您，回答正确"}):
            r = contest.submit_answer(ADAPTER, "tok", "Q2", "flag{x}")
        self.assertTrue(r["ok"], "首次答对(无 status 字段)应判成功")
        # 重复提交(实测): message 不同但带 status=1
        with patch.object(contest, "_request", return_value={"code": 0, "message": "答案正确，该题目已被攻克，不计分", "status": 1}):
            r = contest.submit_answer(ADAPTER, "tok", "Q2", "flag{x}")
        self.assertTrue(r["ok"], "重复提交(status=1)应判成功")
        # 答错: code 非 0
        with patch.object(contest, "_request", return_value={"code": 1, "message": "答案错误", "status": 0}):
            r = contest.submit_answer(ADAPTER, "tok", "Q2", "flag{nope}")
        self.assertFalse(r["ok"])
        self.assertEqual(r["message"], "答案错误")
        # 答错但 code==0 的兜底: "不正确" 不能被 "正确" 子串误命中
        with patch.object(contest, "_request", return_value={"code": 0, "message": "答案不正确", "status": 0}):
            r = contest.submit_answer(ADAPTER, "tok", "Q2", "flag{nope}")
        self.assertFalse(r["ok"], "'答案不正确' 不得误判为正确")

    def test_import_payload(self):
        with patch.object(contest, "_request", return_value=LIST_RESP):
            qs = contest.fetch_questions(ADAPTER, "tok")
        kw = contest.import_payload(ADAPTER, qs[1])
        self.assertEqual(kw["name"], "sign_shellcode")
        self.assertEqual(kw["category"], "re")
        self.assertEqual(kw["target"], "nc 1.2.3.4 2333")
        self.assertEqual(kw["attachment_urls"], [])
        self.assertEqual(kw["contest"]["question_id"], "Q2")
        self.assertTrue(kw["contest"]["interactive"])
        self.assertIn("docker", kw["info"])
        # 未知分类回落 misc
        q = dict(qs[0], category="aiot", category_raw="AIoT")
        self.assertEqual(contest.import_payload(ADAPTER, q)["category"], "misc")


class TokenStoreTests(unittest.TestCase):
    def test_token_roundtrip(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with (
            patch.object(store, "APP_DIR", __import__("pathlib").Path(tmp.name)),
            patch.object(store, "STATE_FILE", __import__("pathlib").Path(tmp.name) / "state.json"),
        ):
            self.assertEqual(store.get_contest_token("mock-ai"), "")
            store.set_contest_token("mock-ai", "tok123")
            self.assertEqual(store.get_contest_token("mock-ai"), "tok123")
            store.set_contest_token("mock-ai", "")
            self.assertEqual(store.get_contest_token("mock-ai"), "")


class SubmitFlagEndpointTests(unittest.TestCase):
    def make_challenge(self, contest_binding):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        ch = store.Challenge(
            id="abc123", name="t", category="pwn", workdir=tmp.name, root=tmp.name,
            tmux={"session": "s"}, status="running", contest=contest_binding,
        )
        ch.save()
        return ch

    def submit(self, ch, flag):
        with patch.object(server, "_get", return_value=ch):
            return server.submit_flag(ch.id, server.FlagIn(flag=flag))

    def test_platform_accept_marks_solved(self):
        ch = self.make_challenge({"adapter": "mock-ai", "question_id": "Q2"})
        with (
            patch.object(contest, "load_adapter", return_value=ADAPTER),
            patch.object(store, "get_contest_token", return_value="tok"),
            patch.object(contest, "submit_answer", return_value={"ok": True, "message": "答案正确"}),
        ):
            r = self.submit(ch, "flag{real}")
        self.assertTrue(r["ok"])
        self.assertTrue(r["saved"])
        reloaded = store.Challenge.load(ch.meta_path)
        self.assertEqual(reloaded.flag, "flag{real}")
        self.assertEqual(reloaded.status, "solved")

    def test_platform_reject_keeps_unsolved(self):
        ch = self.make_challenge({"adapter": "mock-ai", "question_id": "Q2"})
        with (
            patch.object(contest, "load_adapter", return_value=ADAPTER),
            patch.object(store, "get_contest_token", return_value="tok"),
            patch.object(contest, "submit_answer", return_value={"ok": False, "message": "答案错误"}),
        ):
            r = self.submit(ch, "flag{wrong}")
        self.assertFalse(r["ok"])
        self.assertFalse(r["saved"])
        reloaded = store.Challenge.load(ch.meta_path)
        self.assertEqual(reloaded.flag, "")
        self.assertEqual(reloaded.status, "running")

    def test_unbound_challenge_rejected(self):
        ch = self.make_challenge({})
        try:
            self.submit(ch, "flag{x}")
            self.fail("应当 400")
        except Exception as e:
            self.assertIn("未绑定", str(e))


if __name__ == "__main__":
    unittest.main()
