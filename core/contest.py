"""ubz-ctf core: 赛事平台兼容层.

很多比赛不提供题目下载, 只给一套 HTTP 接口(查题/重置环境/提交 flag)。
这里把每个赛事抽象成一个声明式 YAML 适配器, 放在 contests/ 目录:

  apis.list    拉取题目列表 (必需): method/url/ok/data/fields/target_fields
  apis.reset   重置题目环境 (可选)
  apis.submit  提交 flag    (可选)

- url/headers/body 模板变量: {token} {question_id} {answer}; url 里自动 URL 编码
- ok 表达式对响应 JSON 求值(键缺失按 None 处理), 例: "code == 0 and status == 1"
- data/fields 用点分路径取值, 例: "data"、"connection.docker_url", 支持数组下标 "list.0"

新增一个赛事 = 在 contests/ 里加一个 YAML, 不用改代码。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

import requests
import yaml

from . import prompts as _prompts

PROJECT_DIR = Path(__file__).resolve().parent.parent
ADAPTERS_DIR = PROJECT_DIR / "contests"

_UA = {"User-Agent": "ubz-ctf/0.1"}


class ContestError(Exception):
    """适配器或平台侧错误, 消息可直接展示给用户。"""


# ---------------------------------------------------------------- 适配器加载

def list_adapters() -> list[dict]:
    """扫描 contests/*.yaml, 返回适配器列表(带 id/file 字段)。"""
    out = []
    if not ADAPTERS_DIR.is_dir():
        return out
    for f in sorted(ADAPTERS_DIR.glob("*.yaml")):
        try:
            a = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            continue
        if not isinstance(a, dict) or not isinstance(a.get("apis"), dict):
            continue
        a.setdefault("id", f.stem)
        a["file"] = f.name
        out.append(a)
    return out


def load_adapter(adapter_id: str) -> dict:
    for a in list_adapters():
        if a["id"] == adapter_id:
            return a
    raise ContestError(f"赛事适配器不存在: {adapter_id} (应为 contests/ 下的 yaml 文件名)")


def adapter_summary(a: dict) -> dict:
    apis = a.get("apis") or {}
    return {
        "id": a["id"],
        "name": a.get("name") or a["id"],
        "note": a.get("note") or "",
        "supports": {k: isinstance(apis.get(k), dict) for k in ("list", "reset", "submit")},
    }


# ---------------------------------------------------------------- 模板与求值

def _render(template: Any, ctx: dict[str, Any], encode: bool) -> Any:
    """递归渲染 str/list/dict 模板; {var} 替换为 ctx 值, encode=True 时 URL 编码。"""
    if isinstance(template, str):
        out = template
        for k, v in ctx.items():
            if v is None:
                v = ""
            out = out.replace("{" + k + "}", quote(str(v), safe="") if encode else str(v))
        return out
    if isinstance(template, list):
        return [_render(x, ctx, encode) for x in template]
    if isinstance(template, dict):
        return {k: _render(v, ctx, encode) for k, v in template.items()}
    return template


class _Scope(dict):
    """ok 表达式求值作用域: 访问缺失键返回 None 而不是抛 NameError。"""

    def __missing__(self, key: str) -> None:
        return None


def check_ok(expr: str, resp: Any) -> bool:
    """对响应 JSON 求 ok 表达式; 无表达式视为成功, 求值出错视为失败。

    作用域 = 安全内建(str/int/...) + 响应顶层键, 全部放进 globals(自定义 __missing__
    返回 None): 缺失键拿到 None, 函数名正常可调用; 真实内建被 __builtins__={} 屏蔽。
    """
    if not expr:
        return True
    safe = {"str": str, "int": int, "float": float, "len": len, "bool": bool}
    scope = _Scope({**safe, **(resp if isinstance(resp, dict) else {})})
    scope["resp"] = resp
    scope["__builtins__"] = {}
    try:
        return bool(eval(expr, scope))  # noqa: S307 本地配置
    except Exception:
        return False


def dig(obj: Any, path: str) -> Any:
    """点分路径取值: "connection.docker_url", 数组段用数字下标; 取不到返回 None。"""
    cur = obj
    for part in (path or "").split("."):
        if not part:
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)] if int(part) < len(cur) else None
        else:
            return None
    return cur


def _truthy(v: Any) -> bool:
    """平台常把布尔写成字符串 "true"/"false", 统一归一。"""
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return bool(v)


def _msg(resp: Any) -> str:
    if isinstance(resp, dict):
        return str(resp.get("message") or resp.get("msg") or json.dumps(resp, ensure_ascii=False)[:300])
    return str(resp)[:300]


# ---------------------------------------------------------------- HTTP

def _request(spec: dict, ctx: dict[str, Any]) -> Any:
    """按适配器 spec 发请求, 返回解析后的 JSON。代理失败时自动直连重试一次。"""
    if not spec.get("url"):
        raise ContestError("适配器接口缺少 url")
    method = (spec.get("method") or "GET").upper()
    url = _render(spec["url"], ctx, encode=True)
    headers = {**_UA, **(_render(spec.get("headers") or {}, ctx, encode=False))}
    kwargs: dict[str, Any] = {"headers": headers, "timeout": (10, 60)}
    if spec.get("body") is not None:
        kwargs["json"] = _render(spec["body"], ctx, encode=False)

    try:
        resp = requests.request(method, url, **kwargs)
    except requests.RequestException:
        # 本机代理不认 CIDR 写法的 no_proxy 时会 502, 绕开代理直连重试
        sess = requests.Session()
        sess.trust_env = False
        try:
            resp = sess.request(method, url, **kwargs)
        except requests.RequestException as e:
            raise ContestError(f"请求平台接口失败: {e}") from e
    try:
        return resp.json()
    except ValueError as e:
        raise ContestError(f"平台返回非 JSON (HTTP {resp.status_code}): {resp.text[:200]}") from e


# ---------------------------------------------------------------- 题目归一化

def normalize_question(item: dict, spec: dict, adapter: dict) -> dict:
    """按 fields 映射把平台原始题目归一化成统一结构。"""
    fields = spec.get("fields") or {}
    q = {name: dig(item, path) for name, path in fields.items()}
    if not q.get("question_id"):
        raise ContestError(f"题目缺少 question_id 字段, 检查适配器 fields 映射: {str(item)[:120]}")

    raw_cat = str(q.get("category") or "").strip()
    cmap = {str(k).lower(): str(v) for k, v in (adapter.get("category_map") or {}).items()}
    q["category_raw"] = raw_cat
    q["category"] = cmap.get(raw_cat.lower(), raw_cat.lower() or "misc")
    q["interactive"] = _truthy(q.get("interactive"))
    q["is_solved"] = _truthy(q.get("is_solved"))

    target = ""
    for path in spec.get("target_fields") or []:
        v = dig(item, path)
        if v:
            target = str(v).strip()
            break
    if not target:  # 兜底: ip + port 拼接
        conn = q.get("connection")
        if isinstance(conn, dict):
            ip, port = conn.get("docker_ip") or conn.get("ip"), conn.get("docker_port") or conn.get("port")
            if ip and port:
                target = f"{ip}:{port}"
            elif ip:
                target = str(ip)
    q["target"] = target
    return q


def fetch_questions(adapter: dict, token: str) -> list[dict]:
    """调用 list 接口并归一化题目列表。"""
    spec = (adapter.get("apis") or {}).get("list")
    if not isinstance(spec, dict):
        raise ContestError(f"适配器 {adapter['id']} 未定义 list 接口")
    resp = _request(spec, {"token": token})
    if not check_ok(spec.get("ok", ""), resp):
        raise ContestError(f"平台返回错误: {_msg(resp)}")
    data = dig(resp, spec.get("data") or "data")
    if not isinstance(data, list):
        raise ContestError(f"响应里 '{spec.get('data')}' 不是数组, 检查适配器 data 路径")
    return [normalize_question(x, spec, adapter) for x in data if isinstance(x, dict)]


def reset_env(adapter: dict, token: str, question_id: str) -> dict:
    spec = (adapter.get("apis") or {}).get("reset")
    if not isinstance(spec, dict):
        raise ContestError(f"适配器 {adapter['id']} 未定义 reset 接口")
    resp = _request(spec, {"token": token, "question_id": question_id})
    ok = check_ok(spec.get("ok", ""), resp)
    return {"ok": ok, "message": _msg(resp), "raw": resp}


def submit_answer(adapter: dict, token: str, question_id: str, answer: str) -> dict:
    spec = (adapter.get("apis") or {}).get("submit")
    if not isinstance(spec, dict):
        raise ContestError(f"适配器 {adapter['id']} 未定义 submit 接口")
    resp = _request(spec, {"token": token, "question_id": question_id, "answer": answer})
    ok = check_ok(spec.get("ok", ""), resp)
    return {"ok": ok, "message": _msg(resp), "raw": resp}


# ---------------------------------------------------------------- 导入为本地题目

def map_category(cat: str) -> str:
    """归一化后的分类若不在 prompts/ 模板里(也不是 custom), 归为 misc。"""
    return cat if cat in _prompts.categories() else "misc"


def import_payload(adapter: dict, q: dict) -> dict:
    """把归一化题目组装成 store.create_challenge 的参数 + contest 绑定。"""
    parts: list[str] = []
    desc = str(q.get("description") or "").strip()
    if desc:
        parts.append(desc)
    bits = []
    if q.get("score") is not None:
        bits.append(f"分值 {q['score']}")
    if q.get("real_score") is not None and q.get("real_score") != q.get("score"):
        bits.append(f"原始分值 {q['real_score']}")
    if q.get("solved_number") is not None:
        bits.append(f"全场已解 {q['solved_number']} 队")
    for key, label in (("attributes", "标签"), ("capabilities", "能力")):
        vals = q.get(key)
        if isinstance(vals, list) and vals:
            bits.append(f"{label} " + ",".join(str(v) for v in vals))
    if q.get("interactive"):
        bits.append("容器题(平台可重置环境)")
    if bits:
        parts.append("平台信息: " + " · ".join(bits))
    ext = q.get("extensions")
    if isinstance(ext, dict) and ext:
        parts.append("扩展信息: " + json.dumps(ext, ensure_ascii=False))
    if q["category_raw"] and q["category_raw"].lower() != q["category"]:
        parts.append(f"(平台原始分类: {q['category_raw']})")

    return {
        "name": str(q.get("title") or q["question_id"]).strip(),
        "category": map_category(q["category"]),
        "info": "\n\n".join(parts),
        "target": q.get("target") or "",
        "attachment_urls": [q["file_url"]] if q.get("file_url") else [],
        "contest": {
            "adapter": adapter["id"],
            "adapter_name": adapter.get("name") or adapter["id"],
            "question_id": str(q["question_id"]),
            "interactive": q.get("interactive", False),
            "score": q.get("score"),
        },
    }
