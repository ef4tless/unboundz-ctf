"""ubz-ctf core: Jev (TypeSafe System One 决策模型) 语义闸门。

把系统里字符串方法判不准的三处 judgment 交给 Jev 的 noul (校准过的是/否概率,
官方 70-500ms, 输出免费):
  1. 漏洞点接力: 候选条目是不是基线之外的新洞 (措辞改写/依据补充不推)
  2. 求助识别二审: 关键词命中后判"真向人求助/等人介入"还是"只是提到这些词"
  3. 空转检测: 本地已交付的 agent 还在忙, 是实质工作还是等待/轮询烧 token

所有判定不可用时 (gate 未开/没 key/超时/响应缺答案) 一律返回 None,
调用方回退到原有确定性行为——模型故障永远不卡死链路。
API 参考: https://docs.typesafe.ai/introduction/quickstart
"""

from __future__ import annotations

import os

import requests

API_URL = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"


def _call(state: str, questions: dict) -> dict | None:
    """一次 systemone 调用 (多个 noul 问题并行判); 不可用/异常返回 None。"""
    key = os.environ.get("TYPESAFE_API_KEY", "")
    if not key:
        return None
    try:
        resp = requests.post(
            API_URL,
            headers={"Authorization": f"Bearer {key}"},
            json={"state": state, "model": MODEL, "questions": questions},
            timeout=10)
        if resp.status_code != 200:
            return None
        return resp.json().get("answers", {})
    except (requests.RequestException, ValueError):
        return None


def _noul(config: dict, gate: str, threshold_key: str, default_thr: float,
          state: str, instructions: str) -> bool | None:
    """单 noul 判定: gate 未开/调用失败/缺答案 -> None; 否则 概率>=阈值。"""
    if not config.get(gate, False):
        return None
    answers = _call(state, {"q": {"type": "noul", "instructions": instructions}})
    ans = (answers or {}).get("q")
    if not isinstance(ans, dict) or "noul" not in ans:
        return None
    return float(ans["noul"]) >= float(config.get(threshold_key, default_thr))


def judge_help(config: dict, screen_tail: str) -> bool | None:
    """求助二审 (关键词命中后才调用): agent 是真在向人求助, 还是只是提到这些词
    (引用模板/分析讨论/说"不需要")。"""
    return _noul(
        config, "jev_help_gate", "jev_help_threshold", 0.6,
        "一道 CTF 题的解题 agent 终端最近输出：\n" + screen_tail,
        "输出中 agent 正在向人类操作员求助、或停下来等待人工输入/确认/提供信息。"
        "只是提及、引用或讨论相关词汇（包括说自己不需要人工、复述任务要求）判否")


def judge_spin(config: dict, screen_tail: str) -> bool | None:
    """空转判定 (本地已交付+远程未开+仍在忙碌时才调用): 屏幕上的忙碌是实质工作
    还是无产出的等待/轮询 (烧 token)。
    措辞实测校准: 只让 Jev 看界面证据 (等待状态行+token 空涨 vs 新工具调用),
    把"已交付"前提写进 state 会把实质工作也误判成空转 (0.7 vs 空转 0.86,
    分不开); 纯界面证据版分离度 0.82 vs 0.13, 阈值 0.7 有大余地。"""
    return _noul(
        config, "jev_spin_gate", "jev_spin_threshold", 0.7,
        "CTF agent 终端界面：\n" + screen_tail,
        "判断 agent 此刻是否在空转。空转 = 界面停在 Waiting/等待类状态，"
        "没有新的工具调用，只有计时器和 token 计数在涨。非空转 = 界面有新的"
        "命令执行、文件读写、分析输出。拿不准判否")


def filter_new_vulns(config: dict, baseline: list[str],
                     candidates: list[str]) -> list[str] | None:
    """漏洞点接力闸门: 从候选条目里筛出"基线中没有的新漏洞点"。
    返回 None = Jev 不可用, 调用方回退到原有全推行为;
    返回 [] = 判定全是改写/补充/合并, 不该打扰防御路。"""
    if not config.get("jev_vuln_gate", False):
        return None
    if not candidates:
        return []
    state = ("共享黑板「漏洞点」分区有更新。防御路已知/已修的漏洞点基线：\n"
             + ("\n".join(baseline) if baseline else "（空）")
             + "\n———\n候选条目：\n"
             + "\n".join(f"[{i}] {c}" for i, c in enumerate(candidates)))
    answers = _call(state, {
        f"v{i}": {"type": "noul",
                  "instructions": f"候选条目 [{i}] 描述的是一个基线中不存在的、"
                                  "值得立即推给防御路的新漏洞点（不是对基线条目的"
                                  "措辞改写、依据补充或整理合并）"}
        for i in range(len(candidates))
    })
    if answers is None:
        return None
    thr = float(config.get("jev_vuln_threshold", 0.6))
    out: list[str] = []
    for i, cand in enumerate(candidates):
        ans = answers.get(f"v{i}")
        if not isinstance(ans, dict) or "noul" not in ans:
            return None   # 响应缺答案: 不敢静默吞掉推送, 回退
        if float(ans["noul"]) >= thr:
            out.append(cand)
    return out
