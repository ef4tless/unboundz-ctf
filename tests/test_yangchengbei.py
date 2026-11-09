import asyncio
import tempfile
import unittest
from unittest.mock import patch

import server
from core import contest, store


LIST_RESPONSE = {
    "code": "00000", "message": "", "data": [
        {"id": 10, "name": "Web", "order": 1, "corpus": [
            {"id": 1001, "name": "easy-web", "order": 1,
             "isOpen": True, "hasSolved": False},
        ]},
        {"id": 20, "name": "Reverse", "order": 2, "corpus": [
            {"id": 1002, "name": "pending-re", "order": 1,
             "isOpen": True, "hasSolved": True},
        ]},
    ],
}


def detail_response(qid=1001, *, pending=False):
    endpoints = [] if pending else [{
        "exposeIps": ["10.0.0.10"], "ports": ["80", "22"],
        "users": [{"username": "root", "password": "password"}],
        "portMappings": [{"type": "tcp", "port": "80", "proxy": "30080"}],
        "proxyIps": ["1.2.3.4"], "isProxy": False,
        "expireTime": 1780000000000,
    }]
    return {"code": "00000", "message": "", "data": {
        "id": qid, "name": "easy-web" if qid == 1001 else "pending-re",
        "description": "题目描述", "hasSolved": qid == 1002,
        "score": "100", "difficulty": "EASY",
        "attachment": {"files": [
            {"name": "a.zip", "url": "https://example.com/a.zip", "ext": "zip"},
            {"name": "b.zip", "url": "https://example.com/b.zip", "ext": "zip"},
        ]},
        "endpoints": endpoints, "canRefreshEndpoint": False,
        "isNeedInit": pending, "endpointType": "monopoly",
        "currentTime": 1780000000000, "isNeedCheck": pending,
    }}


class YangchengbeiAdapterTests(unittest.TestCase):
    def setUp(self):
        self.adapter = contest.load_adapter("yangchengbei-ai")
        self.host = "https://match.example.com"

    def test_single_attachment_object_is_normalized(self):
        detail = detail_response()
        detail["data"]["attachment"] = {
            "name": "switchyard.zip", "url": "https://example.com/switchyard.zip",
            "extension": "zip",
        }
        summary = {"question_id": 1001, "title": "easy-web",
                   "category": "web", "category_raw": "WEB"}
        with patch.object(contest, "_request", return_value=detail):
            question = contest.fetch_question_detail(
                self.adapter, summary, "ak_test", self.host)
        self.assertEqual(question["file_urls"], ["https://example.com/switchyard.zip"])
        self.assertEqual(contest.import_payload(self.adapter, question)["attachment_urls"],
                         ["https://example.com/switchyard.zip"])

    def test_list_query_does_not_depend_on_detail_rate_limit(self):
        with patch.object(contest, "_request", return_value=LIST_RESPONSE) as request:
            questions = contest.fetch_questions(
                self.adapter, "ak_test", self.host, include_details=False)
        self.assertEqual(len(questions), 2)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(questions[0]["title"], "easy-web")
        self.assertEqual(questions[1]["category"], "re")

    def test_import_normalizes_numeric_ids_and_fetches_only_selected_detail(self):
        summary = {"question_id": 1001, "title": "easy-web",
                   "category": "web", "category_raw": "WEB"}
        with tempfile.TemporaryDirectory() as root, \
             patch.object(server.store, "get_root", return_value=root), \
             patch.object(server.store, "get_competition_mode",
                          return_value=store.MODE_API_AUTO), \
             patch.object(server.store, "get_contest_token", return_value="ak_test"), \
             patch.object(server.store, "get_contest_host", return_value=self.host), \
             patch.object(server.contest_mod, "load_adapter", return_value=self.adapter), \
             patch.object(server.contest_mod, "fetch_questions", return_value=[summary]), \
             patch.object(server.contest_mod, "fetch_question_detail",
                          return_value=summary) as detail:
            result = asyncio.run(server.import_questions(
                "yangchengbei-ai", server.ImportIn(question_ids=["1001"])))

        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["created"]), 1)
        detail.assert_called_once()
        self.assertEqual(detail.call_args.args[1]["question_id"], 1001)

    def test_nested_list_details_targets_and_multiple_attachments(self):
        def fake_request(spec, ctx):
            if "exercise-list" in spec["url"]:
                self.assertEqual(ctx["server_host"], self.host)
                return LIST_RESPONSE
            return detail_response(int(ctx["question_id"]), pending=int(ctx["question_id"]) == 1002)

        with patch.object(contest, "_request", side_effect=fake_request):
            questions = contest.fetch_questions(self.adapter, "ak_test", self.host)

        self.assertEqual(len(questions), 2)
        web, re = questions
        self.assertEqual(web["question_id"], 1001)
        self.assertEqual(web["category"], "web")
        self.assertEqual(web["target"], "10.0.0.10:80")  # isProxy=false 时不能用 proxyIps
        self.assertEqual(web["file_urls"], [
            "https://example.com/a.zip", "https://example.com/b.zip"])
        self.assertFalse(web["environment_pending"])
        self.assertEqual(re["category"], "re")
        self.assertEqual(re["target"], "")
        self.assertTrue(re["interactive"])
        self.assertTrue(re["environment_pending"])

        payload = contest.import_payload(self.adapter, web)
        self.assertEqual(payload["attachment_urls"], web["file_urls"])
        self.assertIn("endpoints", payload["info"])
        self.assertIn("root", payload["info"])

    def test_proxy_target_uses_proxy_ip_and_mapped_port(self):
        detail = detail_response()
        detail["data"]["endpoints"][0]["isProxy"] = True
        with patch.object(contest, "_request", side_effect=[
                LIST_RESPONSE, detail, detail_response(1002, pending=True)]):
            questions = contest.fetch_questions(self.adapter, "ak_test", self.host)
        self.assertEqual(questions[0]["target"], "1.2.3.4:30080")

    def test_submit_uses_access_key_json_and_correctness_gate(self):
        response = type("Response", (), {
            "json": lambda self: {"code": "00000", "message": "", "data": {"isCorrect": True}},
        })()
        with patch.object(contest.requests, "request", return_value=response) as request:
            result = contest.submit_answer(self.adapter, "ak_test", "1001", "flag{x}", self.host)
        self.assertTrue(result["ok"])
        method, url = request.call_args.args
        self.assertEqual(method, "POST")
        self.assertEqual(url, self.host + "/slab-match/api/v1/agent/answer-panel/answer")
        self.assertEqual(request.call_args.kwargs["headers"]["X-Agent-AccessKey"], "ak_test")
        self.assertEqual(request.call_args.kwargs["json"], {"exerciseId": 1001, "flag": "x"})

        for raw, expected in (("DASCTF{AbC123}", "AbC123"),
                              ("AbC123", "AbC123"),
                              ("ya_liE_Ya_LIe_s0m3oNe_geT_f1aG!!}",
                               "ya_liE_Ya_LIe_s0m3oNe_geT_f1aG!!"),
                              ("flag{AbC123", "AbC123"),
                              ("flag{a{b}c}", "a{b}c")):
            with self.subTest(raw=raw), patch.object(
                    contest.requests, "request", return_value=response) as req:
                contest.submit_answer(self.adapter, "ak_test", "1001", raw, self.host)
                self.assertEqual(req.call_args.kwargs["json"]["flag"], expected)

        with patch.object(contest, "_request", return_value={
                "code": "00000", "message": "", "data": {"isCorrect": False}}):
            result = contest.submit_answer(self.adapter, "ak_test", "1001", "bad", self.host)
        self.assertFalse(result["ok"])

    def test_reset_runs_recover_then_build_with_numeric_id(self):
        calls = []
        def fake_request(spec, ctx):
            calls.append((spec["url"], spec.get("body"), ctx))
            if "exercise?" in spec["url"]:
                return detail_response()
            return {"code": "00000", "message": "", "data": {}}

        with patch.object(contest, "_request", side_effect=fake_request):
            result = contest.reset_env(self.adapter, "ak_test", "1001", self.host)
        self.assertTrue(result["ok"])
        self.assertTrue(result["ready"])
        self.assertEqual(result["target"], "10.0.0.10:80")
        self.assertEqual(len(calls), 3)
        self.assertIn("recover-exercise-env", calls[0][0])
        self.assertIn("build-exercise-env", calls[1][0])
        self.assertEqual(calls[0][1], {"exerciseId": "{question_id}"})
        self.assertEqual(calls[1][1], {"exerciseId": "{question_id}"})
        self.assertEqual(calls[0][2]["question_id"], 1001)
        self.assertEqual(calls[1][2]["question_id"], 1001)
    def test_reset_updates_local_target_after_environment_ready(self):
        with tempfile.TemporaryDirectory() as root:
            ch = store.create_challenge(root, name="ready", category="web",
                                        harnesses=["claude"])
            ch.contest = {"adapter": "yangchengbei-ai", "question_id": "1001"}
            ch.save()
            with patch.object(server.store, "get_root", return_value=root), \
                 patch.object(server.store, "get_competition_mode",
                              return_value=store.MODE_API_AUTO), \
                 patch.object(server.store, "get_contest_token", return_value="ak_test"), \
                 patch.object(server.store, "get_contest_host", return_value=self.host), \
                 patch.object(server.contest_mod, "load_adapter", return_value=self.adapter), \
                 patch.object(server.contest_mod, "reset_env", return_value={
                     "ok": True, "ready": True, "target": "10.0.0.10:80"}):
                result = asyncio.run(server.contest_reset("yangchengbei-ai", "1001"))

            self.assertEqual(result["challenge_id"], ch.id)
            self.assertEqual(result["notified"], 0)
            self.assertEqual(store.Challenge.load(ch.meta_path).target, "10.0.0.10:80")
    def test_match_overview_notices_and_notice_detail_queries(self):
        seen = []
        def fake_request(spec, ctx):
            seen.append((spec["url"], ctx))
            if "match-info" in spec["url"]:
                return {"code": "00000", "data": {"note": "注意", "rule": "规则"}}
            if "overview" in spec["url"]:
                return {"code": "00000", "data": {"stagePoint": 88.5, "stageRank": 7}}
            if "now-list" in spec["url"]:
                return {"code": "00000", "data": [{"id": 501, "title": "公告"}]}
            return {"code": "00000", "data": {"id": 501, "content": "公告正文"}}

        with patch.object(contest, "_request", side_effect=fake_request):
            info = contest.query(self.adapter, "match_info", {})
            overview = contest.query(self.adapter, "overview", {})
            notices = contest.query(self.adapter, "notices", {})
            detail = contest.query_detail(self.adapter, "notices", {"item_id": "501"})

        self.assertEqual(info["rule"], "规则")
        self.assertEqual(overview["stageRank"], 7)
        self.assertEqual(notices[0]["id"], 501)
        self.assertEqual(detail["content"], "公告正文")
        self.assertEqual(len(seen), 4)
        self.assertTrue(any("notice/detail?id={item_id}" in url for url, _ in seen))
        self.assertEqual(seen[-1][1]["item_id"], "501")


if __name__ == "__main__":
    unittest.main()
