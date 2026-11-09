"""ubz-ctf: FastAPI 服务端。

启动: uvicorn server:app --host 127.0.0.1 --port 8600
(或直接 python server.py, 见文件末尾)
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import logging
import os
import shlex
import shutil
import stat
import subprocess
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from core import contest as contest_mod
from core import downloader, harness, jevgate, monitor, prompts, store, tmuxctl

PROJECT_DIR = Path(__file__).resolve().parent
CONFIG = store.load_config()
MONITOR = monitor.Monitor(CONFIG)

# 进行中的下载任务: challenge_id -> asyncio.Task
_download_tasks: dict[str, asyncio.Task] = {}
_download_cancel: dict[str, threading.Event] = {}
# 同一路 launch/resume 串行化，防止双击或并发 API 请求重复分配 pane。
_unit_locks: dict[str, asyncio.Lock] = {}
# 全局冷启动槽位按事件循环隔离（测试会创建多个 loop）。
_launch_limiters: dict[asyncio.AbstractEventLoop, asyncio.Semaphore] = {}
_launch_waiting = 0
_launch_active = 0
_background_errors = 0
_background_last_error = ""
_background_last_error_at = 0.0
_background_last_log = 0.0
_resource_limits_supported = False
_resource_gate_reason = ""
logger = logging.getLogger("ubz.server")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    MONITOR.defense_handler = _auto_defense_trigger   # AWDP 漏洞点接力
    await asyncio.to_thread(_probe_resource_limits)
    await asyncio.to_thread(_migrate_competition_modes)
    await asyncio.to_thread(_migrate_tmux_identities)
    MONITOR.start()
    await asyncio.to_thread(MONITOR.seed_deliverables)
    yield
    await MONITOR.stop()


app = FastAPI(title="ubz-ctf", lifespan=lifespan)


@app.exception_handler(contest_mod.ContestError)
async def _contest_error(_req: Request, e: contest_mod.ContestError):
    return JSONResponse(status_code=400, content={"detail": str(e)})


# ---------------------------------------------------------------- models

class RootIn(BaseModel):
    path: str
    create_if_missing: bool = False
    competition_mode: str | None = None   # traditional | api_auto；不传则保留/推断


class ChallengeIn(BaseModel):
    name: str
    category: str
    info: str = ""
    target: str = ""
    attachment_urls: list[str] = []
    harness: str = ""                      # 单路 (兼容旧调用); harnesses 优先
    harnesses: list[str] = []              # 多路并行: 同时开跑的 harness 列表
    awdp: bool = False                     # AWDP 攻防模式 (pwn/web 拓展勾选)
    auto_defense: bool = True              # AWDP 漏洞点接力: 攻击路写下已验证漏洞点自动开防御路
    defense_harness: str = ""              # 自动防御路用的 harness, 空=config defense_harness 兜底
    defense_harnesses: list[str] = []      # 旧版并行防御路(仅 auto_defense=false 时创建即开跑)
    defense_rules: str = ""                # AWDP 防御规则: 修补路径/白名单命令/打包要求
    defense_prompt: str = ""               # 该题自定义防御提示词 (表单预览后改过), 空=用模板文件
    custom_prompt: str = ""
    auto_launch: bool = True


class AttemptIn(BaseModel):
    harness: str
    directive: str = ""        # 该路附加指令 (分工定位/接力提示), 注入时拼在提示词末尾
    role: str = "attack"       # attack | defense (defense 需要该题类型有防御模板)
    auto_launch: bool = True


class MessageIn(BaseModel):
    text: str


class FlagIn(BaseModel):
    flag: str
    attempt: str = ""          # flag 来自哪一路 attempt (aid), 空=未指明
    stop_others: bool = False  # 勾选后停掉其余在跑的路 (默认不停: flag 可能有错/要写 writeup)


class StatusIn(BaseModel):
    status: str
    note: str = ""


class PatchIn(BaseModel):
    """补充/修改题目信息。message 非空则同时发送到 pane。"""
    target: str | None = None
    info: str | None = None
    defense_rules: str | None = None
    awdp: bool | None = None
    auto_defense: bool | None = None      # 开/关漏洞点接力
    defense_harness: str | None = None    # 自动防御路的 harness
    message: str = ""


class TokenIn(BaseModel):
    token: str


class ImportIn(BaseModel):
    question_ids: list[str]
    auto_launch: bool = False
    harness: str = ""                      # 整批默认 harness
    harnesses: dict[str, str] = {}         # 逐题覆盖: question_id -> harness


class BoardUpdateIn(BaseModel):
    content: str | None = None             # 全文覆盖编辑
    section: str = ""                      # 快捷追加的目标分区 (fact/vuln/dead/inbox...)
    entry: str = ""                        # 快捷追加的单条内容
    verified: bool | None = None           # 是否加 [verified]
    notify: bool = False                   # 是否顺带广播提醒在跑各路重读黑板


# ---------------------------------------------------------------- settings

@app.get("/api/config")
def get_config():
    return {
        "harnesses": harness.harness_names(CONFIG),
        "default_harness": CONFIG.get("default_harness", "codex"),
        "defense_harness": CONFIG.get("defense_harness", ""),
        "categories": prompts.categories(),
        "defense_categories": prompts.defense_categories(),
        "terminal_emulator": CONFIG.get("terminal_emulator"),
        "competition_mode": store.get_competition_mode(),
    }


@app.get("/api/health")
def get_health():
    return {
        "ok": True,
        "launch": {
            "limit": max(1, int(CONFIG.get("launch_concurrency", 2))),
            "active": _launch_active,
            "waiting": _launch_waiting,
        },
        "resource_limits": {
            "scope_enabled": _resource_config().get("scope_enabled", False),
            "admission_control": _resource_config().get("admission_control", True),
            "min_available_mb": _resource_config().get("min_available_mb", 1800),
            "max_load_per_cpu": _resource_config().get("max_load_per_cpu", 1.5),
            "gate_reason": _resource_gate_reason,
        },
        "monitor": {
            "last_poll_at": getattr(MONITOR, "last_poll_at", 0),
            "last_poll_duration": getattr(MONITOR, "last_poll_duration", 0),
            "errors": getattr(MONITOR, "error_count", 0),
            "last_error": getattr(MONITOR, "last_error", ""),
            "output_revision": MONITOR.output_revision,
        },
        "background_errors": _background_errors,
        "background_last_error": _background_last_error,
        "background_last_error_at": _background_last_error_at,
    }


@app.get("/api/settings/root")
def get_root():
    return store.list_roots()


@app.put("/api/settings/root")
def put_root(body: RootIn):
    try:
        root = store.set_root(body.path, create=body.create_if_missing,
                              competition_mode=body.competition_mode)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"current_root": root,
            "competition_mode": store.get_competition_mode(root),
            "tmux_session": store.session_name_for_root(root)}


@app.get("/api/templates")
def get_templates():
    """攻击侧按类型 (prompts/<category>.md), 防御侧按类型 (prompts/defense/<category>.md)。
    防御模板供创建表单预览/编辑, 不作为独立类型。"""
    defense = {}
    for cat in prompts.defense_categories():
        defense[cat] = (prompts.DEFENSE_DIR / f"{cat}.md").read_text(encoding="utf-8")
    return {"attack": prompts.list_templates(), "defense": defense}


# ---------------------------------------------------------------- 附件上传

@app.post("/api/challenges/{cid}/attachments")
async def upload_attachments(cid: str, files: list[UploadFile] = File(...)):
    """本地上传赛题附件到 <workdir>/attachments/, 压缩包自动解压。"""
    ch = _get(cid)
    attach_dir = Path(ch.workdir) / "attachments"
    attach_dir.mkdir(exist_ok=True)
    passwords = CONFIG.get("zip_passwords") or []
    saved, errors = [], []
    for idx, uf in enumerate(files):
        name = downloader.sanitize_filename(uf.filename or "") or f"upload_{idx}"
        dest = attach_dir / name
        with open(dest, "wb") as f:
            while chunk := await uf.read(1 << 20):
                f.write(chunk)
        saved.append(name)
        err = await asyncio.to_thread(downloader._extract, dest, attach_dir,
                                      passwords)
        if err:
            errors.append(err)
    # 附件实体同步进各路 attempt 目录 (它们的 attachments 是隔离拷贝不是共享链接)
    synced = await asyncio.to_thread(store.sync_attempt_attachments, ch)
    try:
        prompts.write_prompt_file(ch)
    except OSError:
        pass
    return {"saved": saved, "errors": errors, "synced": synced}


@app.post("/api/challenges/{cid}/defense-template")
async def upload_defense_template(cid: str, file: UploadFile = File(...)):
    """上传 AWDP 交付压缩包模板 (平台给的 update.tar.gz 骨架)。
    原始保存到 attachments/ 不解压——模板包要保持原样, 防御路自己解开参照结构;
    文件名记进 ch.defense_template, 注入防御提示词的 {防御模板}。"""
    ch = _get(cid)
    name = downloader.sanitize_filename(file.filename or "") or "defense_template.tar.gz"
    dest = Path(ch.workdir) / "attachments" / name
    dest.parent.mkdir(exist_ok=True)
    with open(dest, "wb") as f:
        while chunk := await file.read(1 << 20):
            f.write(chunk)
    ch.defense_template = name
    ch.save()
    synced = await asyncio.to_thread(store.sync_attempt_attachments, ch)
    return {"saved": name, "synced": synced}


# ---------------------------------------------------------------- challenges

# Web 看板快照：meta 的 stat 签名用来识别变化，未变化的题目直接复用
# 已序列化的视图对象。历史里只保存 id/stat，不保存输出正文，内存占用有界。
_DASHBOARD_META_CACHE: OrderedDict[str, tuple[tuple[int, int], dict]] = OrderedDict()
_DASHBOARD_HISTORY: OrderedDict[str, dict] = OrderedDict()
_DASHBOARD_META_CACHE_LIMIT = 256
_DASHBOARD_HISTORY_LIMIT = 48

_DASHBOARD_CH_FIELDS = (
    "id", "name", "category", "info", "target", "attachment_urls", "harness",
    "awdp", "auto_defense", "workdir", "root", "tmux", "status", "flag",
    "flag_attempt", "note", "download_status", "contest",
    "board_entries", "board_updated", "deliverables", "created_at",
)
_DASHBOARD_UNIT_FIELDS = (
    "id", "harness", "role", "status", "workdir", "tmux",
    "note", "port_base", "directive", "spin_suspected", "idle_at_prompt",
    "created_at",
)


def _dashboard_challenge(ch: store.Challenge) -> dict:
    """看板需要的字段；完整 meta 仍由默认 API 与单题 API 提供。"""
    data = {k: getattr(ch, k) for k in _DASHBOARD_CH_FIELDS}
    data["attempts"] = [
        {k: a[k] for k in _DASHBOARD_UNIT_FIELDS if k in a}
        for a in ch.attempts
    ]
    # 卡片只展示漏洞点数量，原文在打开黑板时再按需读取。
    data["vuln_count"] = len(ch.vuln_points)
    return data


def _dashboard_versions(root: str) -> dict[str, tuple[int, int]]:
    versions: dict[str, tuple[int, int]] = {}
    root_path = Path(root)
    if not root_path.is_dir():
        return versions
    try:
        children = sorted(root_path.iterdir())
    except OSError:
        return versions
    for child in children:
        meta = child / "meta.json"
        try:
            st = meta.stat()
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            versions[str(meta)] = (st.st_mtime_ns, st.st_size)
    return versions


def _dashboard_revision(root: str, view: str,
                        versions: dict[str, tuple[int, int]],
                        competition_mode: str = "") -> str:
    h = hashlib.sha256()
    h.update((view + "\0" + competition_mode + "\0" + root + "\0").encode())
    for path, (mtime_ns, size) in versions.items():
        h.update(f"{path}\0{mtime_ns}\0{size}\0".encode())
    return h.hexdigest()


def _dashboard_load(path: str, version: tuple[int, int], view: str) -> dict | None:
    key = view + "\0" + path
    cached = _DASHBOARD_META_CACHE.get(key)
    if cached and cached[0] == version:
        # 不做 LRU move：FastAPI 的 sync endpoint 可并发执行，FIFO 淘汰足够且
        # 不会在两请求之间出现 move_to_end 的 KeyError。
        return cached[1]
    try:
        ch = store.Challenge.load(Path(path))
        data = _dashboard_challenge(ch) if view == "dashboard" else vars(ch)
    except (json.JSONDecodeError, OSError, TypeError, ValueError):
        _DASHBOARD_META_CACHE.pop(key, None)
        return None
    _DASHBOARD_META_CACHE[key] = (version, data)
    while len(_DASHBOARD_META_CACHE) > _DASHBOARD_META_CACHE_LIMIT:
        _DASHBOARD_META_CACHE.popitem(last=False)
    return data


def _remember_dashboard_revision(revision: str, root: str, view: str,
                                 versions: dict[str, tuple[int, int]],
                                 ids: dict[str, str]) -> None:
    _DASHBOARD_HISTORY[revision] = {
        "root": root, "view": view, "versions": versions, "ids": ids,
    }
    while len(_DASHBOARD_HISTORY) > _DASHBOARD_HISTORY_LIMIT:
        _DASHBOARD_HISTORY.popitem(last=False)


def _dashboard_snapshot(root: str, since: str, view: str,
                        output_since: int = 0) -> dict:
    versions = _dashboard_versions(root)
    competition_mode = store.get_competition_mode(root)
    revision = _dashboard_revision(root, view, versions, competition_mode)
    output_revision = MONITOR.output_revision if view == "dashboard" else 0
    base = {
        "root": root,
        "tmux_session": store.session_name_for_root(root),
        "elsewhere_running": MONITOR.elsewhere_running,
        "competition_mode": competition_mode,
        "revision": revision,
        "output_revision": output_revision,
    }
    if view == "dashboard" and output_since != output_revision:
        # 发布后的 outputs 不再原地修改，sync endpoint 可安全共享引用。
        base["outputs"] = MONITOR.outputs.get(root, {})
    if since == revision:
        return {**base, "delta": True, "unchanged": "outputs" not in base,
                "challenges": [], "removed": []}

    old = _DASHBOARD_HISTORY.get(since) if since else None
    incremental = bool(old and old["root"] == root and old["view"] == view)
    old_versions = old["versions"] if incremental else {}
    old_ids = old["ids"] if incremental else {}
    paths = ([path for path, ver in versions.items() if old_versions.get(path) != ver]
             if incremental else list(versions))

    loaded = {path: _dashboard_load(path, versions[path], view) for path in paths}
    removed: list[str] = []
    ids: dict[str, str] = {}
    if incremental:
        ids = {path: cid for path, cid in old_ids.items()
               if path in versions and path not in loaded}
        for path, cid in old_ids.items():
            if path not in versions:
                removed.append(cid)
            elif path in loaded and (loaded[path] is None
                                     or loaded[path].get("id") != cid):
                removed.append(cid)
    for path, data in loaded.items():
        if data is not None:
            ids[path] = data["id"]

    challenges = [data for data in loaded.values() if data is not None]
    if not incremental:
        challenges.sort(key=lambda c: c.get("created_at", 0))
    _remember_dashboard_revision(revision, root, view, versions, ids)
    return {**base, "delta": incremental, "unchanged": False,
            "challenges": challenges, "removed": removed}


@app.get("/api/challenges")
def list_challenges(since: str = "", view: str = "", output_since: int = 0):
    """看板列表。view=dashboard 精简字段；since=<revision> 只回传变化题目。

    不带参数时保持完整字段，供既有脚本使用。revision 由 meta 的 mtime_ns+size
    推导；历史失效时自动回退全量，不会让客户端停留在旧状态。
    """
    root = store.get_root()
    if not root:
        return {"root": None, "challenges": [], "removed": [],
                "competition_mode": store.MODE_TRADITIONAL,
                "revision": "", "delta": False, "unchanged": False,
                "output_revision": MONITOR.output_revision}
    view = "dashboard" if view == "dashboard" else "full"
    return _dashboard_snapshot(root, since, view, output_since)


def _start_download(ch: store.Challenge) -> None:
    cancel = threading.Event()
    _download_cancel[ch.id] = cancel
    task = asyncio.create_task(asyncio.to_thread(
        downloader.download_all, ch, CONFIG, cancel))
    _download_tasks[ch.id] = task
    task.add_done_callback(
        lambda t, cid=ch.id: _download_cancel.pop(cid, None)
        if not t.cancelled() else None)


def _cancel_download(cid: str) -> None:
    cancel = _download_cancel.pop(cid, None)
    if cancel:
        cancel.set()
    task = _download_tasks.pop(cid, None)
    if task is not None:
        task.cancel()


@app.post("/api/challenges", status_code=201)
async def create_challenge(body: ChallengeIn):
    root = store.get_root()
    if not root:
        raise HTTPException(400, "未设置根目录, 请先 PUT /api/settings/root")
    if body.category != "custom" and body.category not in prompts.list_templates():
        raise HTTPException(400, f"未知类型: {body.category}")
    if body.category == "custom" and not body.custom_prompt.strip():
        raise HTTPException(400, "custom 类型必须填写自定义提示词")
    if body.awdp and not prompts.has_defense_template(body.category):
        raise HTTPException(400, f"AWDP 目前只支持有防御模板的类型 "
                                 f"({', '.join(prompts.defense_categories())})")
    if (body.defense_harnesses or body.defense_harness
            or body.defense_prompt.strip()) and not body.awdp:
        raise HTTPException(400, "防御路/防御提示词只在 AWDP 模式下可用, 请先勾选 AWDP")

    harnesses = list(dict.fromkeys(
        h for h in (body.harnesses or [body.harness or CONFIG.get("default_harness", "codex")])
        if h))
    defense = list(dict.fromkeys(h for h in body.defense_harnesses if h))
    # 自动防御路的 harness: 显式指定 > 旧版防御路列表第一个 > config 兜底 (留到触发时取)
    def_harness = body.defense_harness or (defense[0] if defense else "")
    try:
        for h in harnesses + defense + ([def_harness] if def_harness else []):
            harness.launch_command(CONFIG, h)   # 未配置的 harness 尽早报错
    except ValueError as e:
        raise HTTPException(400, str(e))

    ch = store.create_challenge(
        root, name=body.name, category=body.category, info=body.info,
        target=body.target, attachment_urls=body.attachment_urls,
        harness=harnesses[0], custom_prompt=body.custom_prompt,
        harnesses=harnesses, defense_harnesses=defense,
        defense_rules=body.defense_rules, defense_prompt=body.defense_prompt,
        awdp=body.awdp, auto_defense=body.auto_defense,
        defense_harness=def_harness)

    if ch.attachment_urls:
        ch.status = "downloading"
        ch.save()
        _start_download(ch)
    else:
        ch.status = "ready"
        ch.save()

    if body.auto_launch:
        _mark_launching(ch)
        _spawn_bg(_launch(ch))
    return vars(store.Challenge.load(ch.meta_path))


@app.get("/api/challenges/{cid}")
def get_challenge(cid: str):
    return vars(_get(cid))


@app.post("/api/challenges/{cid}/launch")
async def launch(cid: str):
    ch = _get(cid)
    _mark_launching(ch)
    _spawn_bg(_launch(ch))
    return vars(store.Challenge.load(ch.meta_path))


async def _resume_unit(ch: store.Challenge, unit: dict,
                       custom_nudge: str = "") -> None:
    async with _unit_lock(ch, unit):
        fresh = await asyncio.to_thread(_fresh_running_unit, ch, unit)
        if fresh is not None:
            unit["status"] = fresh["status"]
            unit["tmux"].update(fresh["tmux"])
            return   # 重复 resume：已经在跑，幂等返回
        async with _launch_slot():
            await _resume_unit_locked(ch, unit, custom_nudge)


async def _resume_unit_locked(ch: store.Challenge, unit: dict,
                              custom_nudge: str = "") -> None:
    """恢复单路会话并自动续跑; custom_nudge 非空时用它替代默认续跑指令。"""
    store.ensure_collab_files(ch)
    fresh_start = not unit["prompt_sent"]
    uid = _ensure_unit_identity(ch, unit)
    _save_unit_state(ch, unit)   # 先持久化 UUID，再向任何 pane 发命令
    cmd = (harness.launch_command if fresh_start
           else harness.resume_command)(CONFIG, unit["harness"])
    cmd = _resource_limited_command(ch, unit, cmd)
    pane = unit["tmux"].get("pane", "")
    if _unit_pane_exists(ch, unit):
        current = tmuxctl.pane_current_command(pane)
        if current and current not in tmuxctl.SHELL_CMDS:
            raise ValueError(
                f"该路 pane 正在运行 {current}，拒绝注入 {unit['harness']} 恢复命令；"
                "请先确认终端状态")
        # 先记基线再发命令: 命令发出后 harness 可能秒退, 之后再记就把新退出吞了
        unit["exit_seen"] = tmuxctl.exit_mark_count(pane)
        tmuxctl.send_command(pane, f"{cmd}; echo {tmuxctl.EXIT_MARK}$?")
        harness.wait_ready(pane, unit["harness"])
    else:
        tm = await asyncio.to_thread(
            tmuxctl.allocate_pane, ch.tmux["session"], _win_name(ch, unit),
            unit["workdir"], int(CONFIG.get("panes_per_window", 4)), ubz_id=uid)
        unit["tmux"].update(tm)
        pane = tm["pane"]
        tmuxctl.send_command(pane, _unit_env_command(ch, unit, uid))
        tmuxctl.launch_harness(pane, cmd)
        harness.wait_ready(pane, unit["harness"])
        unit["exit_seen"] = 0
    if fresh_start:
        prompt_text = _attempt_prompt(ch, unit)
        if custom_nudge:
            prompt_text += f"\n\n{custom_nudge}"
        tmuxctl.send_text(pane, prompt_text)
        unit["prompt_sent"] = True
    else:
        # 关键一步: 恢复会话只是回到输入框, 推一下才真正继续解题
        if custom_nudge:
            nudge = custom_nudge
        elif unit.get("role") == "defense":
            nudge = harness.DEFENSE_RESUME_NUDGE
        elif ch.target.strip():
            nudge = f"{harness.RESUME_NUDGE}（当前远程靶机地址：{ch.target.strip()}）"
        else:
            nudge = harness.RESUME_NUDGE
        await asyncio.to_thread(harness.nudge_to_continue, pane, unit["harness"],
                                nudge_text=nudge)
    unit["status"] = "running"
    _save_unit_state(ch, unit)


@app.post("/api/challenges/{cid}/resume")
async def resume(cid: str, aid: str = ""):
    """真正的恢复: resume 命令恢复会话 -> 处理弹窗 -> 无 goal 自动续跑时发续跑指令。
    提示词从未送达过(如启动即失败)则全新启动+注入。多开题用 ?aid= 指定哪一路。"""
    ch = _get(cid)
    try:
        unit = store.find_unit(ch, aid)
    except ValueError as e:
        raise HTTPException(400, str(e))
    try:
        await _resume_unit(ch, unit)
    except (tmuxctl.TmuxError, ValueError, OSError) as e:
        raise HTTPException(500, str(e))
    return vars(store.Challenge.load(ch.meta_path))


@app.post("/api/challenges/{cid}/attempts", status_code=201)
async def add_attempt(cid: str, body: AttemptIn):
    """加开一路: 建 runs/<harness>/ 目录 + 共享黑板/附件链接 + 端口段, 默认立即启动。"""
    ch = _get(cid)
    try:
        harness.launch_command(CONFIG, body.harness)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if body.role not in ("attack", "defense"):
        raise HTTPException(400, f"未知 role: {body.role} (可选: attack/defense)")
    if body.role == "defense":
        if not ch.awdp:
            raise HTTPException(400, "该题未开 AWDP 模式, 开不了防御路 "
                                     "(PATCH 可补开 awdp)")
        if not prompts.has_defense_template(ch.category):
            raise HTTPException(400, f"类型 {ch.category} 没有防御模板, 开不了防御路")
    att = store.add_attempt(ch, body.harness, directive=body.directive, role=body.role)
    if body.auto_launch:
        att["status"] = "launching"
        ch.status = store.aggregate_status(ch)
        ch.save()
        _spawn_bg(_launch_attempt(ch, att))
    else:
        ch.status = store.aggregate_status(ch)
        ch.save()
    return vars(store.Challenge.load(ch.meta_path))


@app.delete("/api/challenges/{cid}/attempts/{aid}")
def delete_attempt(cid: str, aid: str, files: bool = False):
    """删除某一路: 杀 pane, 从 attempts 移除 (agent 被安全策略拒答/跑偏时删了重开)。
    files=true 连同该路工作目录一起删; 旧题转换的 a0 住主目录, 主目录永远不动。"""
    ch = _get(cid)
    if not ch.attempts:
        raise HTTPException(400, "旧版单路题没有 attempt, 要删请删整题")
    if len(ch.attempts) <= 1:
        raise HTTPException(400, "只剩最后一路, 要删请删整题")
    att = next((a for a in ch.attempts if a.get("id") == aid), None)
    if att is None:
        raise HTTPException(404, f"题目 {ch.name} 没有 attempt {aid}")
    _kill_unit_pane(ch, att)
    if files and Path(att["workdir"]).resolve() != Path(ch.workdir).resolve():
        shutil.rmtree(att["workdir"], ignore_errors=True)
    store.remove_attempt(ch, aid)
    return vars(store.Challenge.load(ch.meta_path))


@app.delete("/api/challenges/{cid}")
def delete_challenge(cid: str, files: bool = False):
    """删除题目: 杀掉所有路的 pane, 移除出面板。files=true 时连同题目目录一起删除。"""
    ch = _get(cid)
    _cancel_download(cid)
    for unit in store.unit_views(ch):
        _kill_unit_pane(ch, unit)
    if files:
        shutil.rmtree(ch.workdir, ignore_errors=True)
    else:
        Path(ch.meta_path).unlink(missing_ok=True)
    return {"ok": True, "files_deleted": files}


@app.post("/api/challenges/{cid}/message")
def send_message(cid: str, body: MessageIn, aid: str = ""):
    """发消息: 多开题默认广播给所有运行中的路, ?aid= 只发指定那一路。"""
    ch = _get(cid)
    if not body.text.strip():
        raise HTTPException(400, "消息为空")
    units = _message_units(ch, aid)
    sent = 0
    for unit in units:
        pane = unit["tmux"].get("pane", "")
        if pane and _unit_pane_exists(ch, unit):
            tmuxctl.send_text(pane, body.text)
            sent += 1
    if not sent:
        raise HTTPException(400, "没有存活且运行中的 pane, 消息未发送")
    return {"ok": True, "sent": sent}


def _message_units(ch: store.Challenge, aid: str = "") -> list[dict]:
    """消息目标: 指定 aid 给那一路(校验 agent 存活); 否则所有运行中的路。"""
    if aid:
        try:
            unit = store.find_unit(ch, aid)
        except ValueError as e:
            raise HTTPException(400, str(e))
        pane = unit["tmux"].get("pane", "")
        if not pane or not _unit_pane_exists(ch, unit):
            raise HTTPException(400, f"{aid} 的 pane 不存在或身份已变化, 无法发送")
        cur = tmuxctl.pane_current_command(pane)
        if cur in tmuxctl.SHELL_CMDS:
            raise HTTPException(400, f"{aid} 的 agent 未在运行(pane 里是 shell), 消息未发送")
        return [unit]
    return [u for u in store.unit_views(ch)
            if u["tmux"].get("pane") and _unit_pane_exists(ch, u)
            and tmuxctl.pane_current_command(u["tmux"]["pane"]) not in tmuxctl.SHELL_CMDS]


@app.patch("/api/challenges/{cid}")
async def patch_challenge(cid: str, body: PatchIn):
    """补充靶机/更新题目信息; message 非空时广播给所有运行中路里的 agent,
    若攻击路已退出(本地打通后 exited/pane_gone)则自动恢复唤醒并注入消息。"""
    ch = _get(cid)
    changed = False
    if body.target is not None and body.target.strip() != ch.target:
        ch.target = body.target.strip()
        changed = True
    if body.info is not None and body.info != ch.info:
        ch.info = body.info
        changed = True
    if body.defense_rules is not None and body.defense_rules != ch.defense_rules:
        ch.defense_rules = body.defense_rules
        changed = True
    if body.awdp is not None and body.awdp != ch.awdp:
        if body.awdp and not prompts.has_defense_template(ch.category):
            raise HTTPException(400, f"AWDP 目前只支持有防御模板的类型 "
                                     f"({', '.join(prompts.defense_categories())})")
        ch.awdp = body.awdp
        if body.awdp:
            # 漏洞点接力要求单攻击路期间也有黑板/纪律文件可写
            store.ensure_collab_files(ch)
        changed = True
    if body.auto_defense is not None and body.auto_defense != ch.auto_defense:
        ch.auto_defense = body.auto_defense
        changed = True
    if (body.defense_harness is not None
            and body.defense_harness != ch.defense_harness):
        if body.defense_harness:
            try:
                harness.launch_command(CONFIG, body.defense_harness)
            except ValueError as e:
                raise HTTPException(400, str(e))
        ch.defense_harness = body.defense_harness
        changed = True
    if changed:
        ch.save()
        try:
            prompts.write_prompt_file(ch)   # 磁盘记录同步为最新
        except OSError:
            pass
    msg = body.message.strip()
    if msg:
        running_units = _message_units(ch)
        running_ids = {u.get("id") for u in running_units}
        delivered = 0
        for unit in running_units:
            tmuxctl.send_text(unit["tmux"]["pane"], msg)
            delivered += 1
        # 对已退出/窗口丢失的攻击路(或无运行路时的待启动路)自动恢复并注入新靶机消息
        dormant = [
            u for u in store.unit_views(ch)
            if u.get("id") not in running_ids
            and u.get("role", "attack") != "defense"
            and u.get("status") in (
                ("exited", "pane_gone", "stopped", "ready") if not running_units
                else ("exited", "pane_gone")
            )
        ]
        for unit in dormant:
            try:
                await _resume_unit(ch, unit, custom_nudge=msg)
                delivered += 1
            except (tmuxctl.TmuxError, ValueError, OSError):
                continue
        if not delivered:
            raise HTTPException(400, "信息已保存, 但没有可接收或可恢复的 agent, 消息未发送")
        ch = store.Challenge.load(ch.meta_path) if ch.meta_path.is_file() else ch
        ch.supplements.append({"ts": time.time(), "text": msg})
        ch.save()
    return vars(ch)


@app.post("/api/challenges/{cid}/focus")
def focus(cid: str, aid: str = ""):
    ch = _get(cid)
    try:
        unit = store.find_unit(ch, aid)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not unit["tmux"].get("pane"):
        raise HTTPException(400, "该路尚未启动")
    try:
        msg = tmuxctl.spawn_terminal(
            CONFIG.get("terminal_emulator", "gnome-terminal"), unit["tmux"])
    except tmuxctl.TmuxError as e:
        raise HTTPException(500, str(e))
    return {"ok": True, "message": msg}


@app.post("/api/challenges/{cid}/stop")
def stop(cid: str, aid: str = ""):
    """停止: ?aid= 停指定那一路, 否则停掉整组所有 pane。"""
    ch = _get(cid)
    try:
        units = [store.find_unit(ch, aid)] if aid else store.unit_views(ch)
    except ValueError as e:
        raise HTTPException(400, str(e))
    for unit in units:
        _kill_unit_pane(ch, unit)
        unit["status"] = "stopped"
        store.apply_unit(ch, unit)
    ch.status = store.aggregate_status(ch) if ch.attempts else "stopped"
    ch.save()
    return vars(ch)


def _stop_group_after_solve(ch: store.Challenge) -> None:
    """first-flag-wins: 一路(或人)拿到 flag 后, 优雅停掉其余还在跑的路
    (双击 C-c 退出 harness, pane 留着可回看; 进程退回 shell 由 monitor 标 exited)。"""
    for unit in store.unit_views(ch):
        pane = unit["tmux"].get("pane", "")
        if not pane or not _unit_pane_exists(ch, unit):
            continue
        cur = tmuxctl.pane_current_command(pane)
        if cur and cur not in tmuxctl.SHELL_CMDS:
            tm = unit["tmux"]
            tmuxctl.interrupt_pane(
                pane, session=tm.get("session", "") or ch.tmux.get("session", ""),
                ubz_id=tm.get("ubz_id", ""),
                harness_name=unit.get("harness", ""))


@app.post("/api/challenges/{cid}/flag")
def set_flag(cid: str, body: FlagIn):
    ch = _get(cid)
    if body.attempt and body.attempt not in {a.get("id") for a in ch.attempts}:
        raise HTTPException(400, f"未知 attempt: {body.attempt}")
    ch.flag = body.flag.strip()
    if ch.flag:
        ch.flag_candidate = ""
        ch.flag_attempt = body.attempt
        ch.status = "solved"
        ch.save()
        if body.stop_others:
            _stop_group_after_solve(ch)
    elif ch.status == "solved":
        # `solved` is derived from a non-empty manually confirmed flag.  Do not
        # leave the challenge solved after that flag is removed; recover the
        # most accurate current state from its pane instead.
        ch.flag_attempt = ""
        ch.status = _status_without_flag(ch)
        ch.save()
    else:
        ch.save()
    return vars(ch)


@app.post("/api/challenges/{cid}/status")
def set_status(cid: str, body: StatusIn):
    ch = _get(cid)
    if body.status not in store.STATUSES:
        raise HTTPException(400, f"未知状态, 可选: {sorted(store.STATUSES)}")
    ch.status = body.status
    if body.note:
        ch.note = body.note
    ch.save()
    return vars(ch)


@app.get("/api/challenges/{cid}/board")
def get_board(cid: str):
    """读共享黑板原文 (多开题的协作证据板)。"""
    ch = _get(cid)
    board = Path(ch.workdir) / "board.md"
    if not board.is_file():
        return {"exists": False, "content": "", "entries": 0, "updated": 0}
    try:
        content = board.read_text(encoding="utf-8")
    except OSError as e:
        raise HTTPException(500, f"读取 board.md 失败: {e}")
    return {"exists": True, "content": content,
            "entries": ch.board_entries, "updated": ch.board_updated}


@app.put("/api/challenges/{cid}/board")
def put_board(cid: str, body: BoardUpdateIn):
    """编辑共享黑板原文或按分区快捷追加一条记录, 可选顺带提醒在跑各路重读黑板。"""
    ch = _get(cid)
    board = Path(ch.workdir) / "board.md"
    try:
        if body.content is not None:
            board.write_text(body.content, encoding="utf-8")
        elif body.entry.strip():
            store.append_board_entry(
                board,
                body.section or "fact",
                body.entry.strip(),
                verified=body.verified,
                source="人工",
            )
        elif not board.is_file():
            board.write_text(store.BOARD_MD, encoding="utf-8")
    except OSError as e:
        raise HTTPException(500, f"写入 board.md 失败: {e}")

    # 立即刷新黑板条目计数与漏洞点/交付物解析
    MONITOR._poll_board(ch)
    ch.save()

    notified = 0
    if body.notify:
        units = _message_units(ch, "")
        note_msg = (
            "【黑板更新】共享黑板 board.md 有新情报或人工纠偏批注，"
            "请先执行 `cat board.md` 阅读最新内容（特别是 Facts 与 Dead-ends），再继续推进。"
        )
        for u in units:
            pane = u.get("tmux", {}).get("pane", "")
            if pane:
                tmuxctl.send_text(pane, note_msg)
                notified += 1

    content = board.read_text(encoding="utf-8") if board.is_file() else ""
    return {
        "exists": board.is_file(),
        "content": content,
        "entries": ch.board_entries,
        "updated": ch.board_updated,
        "notified": notified,
    }


@app.get("/api/challenges/{cid}/output")
def get_output(cid: str, lines: int = 80, aid: str = ""):
    ch = _get(cid)
    try:
        unit = store.find_unit(ch, aid)
    except ValueError as e:
        raise HTTPException(400, str(e))
    pane = unit["tmux"].get("pane", "")
    if not pane or not _unit_pane_exists(ch, unit):
        return {"output": unit["last_output"], "live": False}
    try:
        return {"output": tmuxctl.capture(pane, lines=lines), "live": True}
    except tmuxctl.TmuxError as e:
        return {"output": "", "live": False, "error": str(e)}


_SKIP_ARTIFACT_DIRS = {
    "attachments", ".git", "__pycache__", "node_modules", ".venv", "venv", "runs",
}
_SKIP_ARTIFACT_FILES = {"meta.json", "AGENTS.md", "CLAUDE.md"}
_ARTIFACT_TEXT_EXTS = {
    ".txt", ".md", ".py", ".sh", ".json", ".yaml", ".yml", ".c", ".cpp", ".js",
}


def _artifact_priority(rel: str) -> tuple[int, str]:
    low = Path(rel).name.lower()
    if low.startswith("flag") and low.endswith(".txt"):
        return (0, rel)
    if "writeup" in low or low == "patch.md":
        return (1, rel)
    if low.startswith(("exp", "solve", "exploit")) and low.endswith((".py", ".sh")):
        return (2, rel)
    if low == "board.md":
        return (3, rel)
    if low == "prompt.md":
        return (5, rel)
    return (4, rel)


@app.get("/api/challenges/{cid}/files")
def get_challenge_files(cid: str, aid: str = ""):
    """列出该路(及题目主目录)下的关键产出文件(flag.txt / writeup.md / exp.py 等)供前端直接查阅复制。"""
    ch = _get(cid)
    units = store.unit_views(ch)
    unit = next((u for u in units if u.get("id") == aid), units[0])
    unit_dir = Path(unit["workdir"])
    main_dir = Path(ch.workdir)
    pkg_name = store.deliverable_name(ch)

    found: dict[str, dict] = {}

    def _scan_dir(base: Path, prefix: str = "", max_depth: int = 2) -> None:
        if not base.is_dir():
            return
        for p in sorted(base.rglob("*")):
            try:
                rel_parts = p.relative_to(base).parts
            except ValueError:
                continue
            if len(rel_parts) > max_depth:
                continue
            if any(part in _SKIP_ARTIFACT_DIRS or part.startswith(".") for part in rel_parts[:-1]):
                continue
            if p.name in _SKIP_ARTIFACT_FILES or p.name.startswith("."):
                continue
            if not p.is_file():
                continue
            try:
                st = p.stat()
            except OSError:
                continue
            rel = prefix + "/".join(rel_parts)
            if p.name in (pkg_name, "update.tar.gz"):
                found.setdefault(rel, {
                    "name": rel,
                    "path": str(p),
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                    "content": f"# 压缩包产物\n路径: {p}\n大小: {st.st_size} 字节\n",
                })
                continue
            if p.suffix.lower() not in _ARTIFACT_TEXT_EXTS or st.st_size == 0 or st.st_size > 262144:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")[:65536]
            except OSError:
                continue
            found.setdefault(rel, {
                "name": rel,
                "path": str(p),
                "size": st.st_size,
                "mtime": st.st_mtime,
                "content": text,
            })

    _scan_dir(unit_dir)
    if unit_dir.resolve() != main_dir.resolve():
        _scan_dir(main_dir, prefix="[主目录] ", max_depth=1)

    files = sorted(found.values(), key=lambda x: _artifact_priority(x["name"]))
    return {"files": files}


# ---------------------------------------------------------------- 赛事平台兼容层

def _require_api_auto(root: str = "") -> None:
    if store.get_competition_mode(root or None) != store.MODE_API_AUTO:
        raise HTTPException(
            400, "当前赛事根目录是传统 CTF 模式，未启用 API 平台接入；"
            "请先在根目录设置中显式切换为 API 全自动赛事")


def _contest_host(adapter: dict, root: str, explicit: str = "") -> str:
    host = explicit.strip() or store.get_contest_host(adapter["id"], root)
    spec = adapter.get("server_host") or {}
    if spec.get("required") and not host:
        raise HTTPException(400, f"请填写 {spec.get('label') or '比赛服务地址'}")
    return host.rstrip("/")


@app.get("/api/contests")
def list_contests():
    """仅 API 模式扫描适配器；传统模式不读取 YAML 或平台 Token。"""
    root = store.get_root() or ""
    if store.get_competition_mode(root or None) != store.MODE_API_AUTO:
        return {"competition_mode": store.MODE_TRADITIONAL, "contests": []}
    out = []
    for a in contest_mod.list_adapters():
        s = contest_mod.adapter_summary(a)
        s["has_token"] = bool(store.get_contest_token(a["id"], root))
        s["server_host"] = {**s["server_host"],
                            "value": store.get_contest_host(a["id"], root)}
        out.append(s)
    return {"competition_mode": store.MODE_API_AUTO, "contests": out}


def _query_context(adapter: dict, root: str, item_id: str = "",
                   token: str = "", server_host: str = "") -> dict:
    token = token.strip() or store.get_contest_token(adapter["id"], root)
    if not token:
        raise HTTPException(400, "未保存平台 token, 请先同步一次赛事信息")
    return {"token": token,
            "server_host": _contest_host(adapter, root, server_host),
            "item_id": item_id, "notice_id": item_id}


@app.get("/api/contests/{cid}/queries/{name}")
def contest_query(cid: str, name: str, token: str = "", server_host: str = ""):
    _require_api_auto()
    root = store.get_root() or ""
    adapter = contest_mod.load_adapter(cid)
    data = contest_mod.query(adapter, name, _query_context(
        adapter, root, token=token, server_host=server_host))
    return {"name": name, "data": data}


@app.get("/api/contests/{cid}/queries/{name}/detail")
def contest_query_detail(cid: str, name: str, item_id: str = "",
                         token: str = "", server_host: str = ""):
    _require_api_auto()
    root = store.get_root() or ""
    adapter = contest_mod.load_adapter(cid)
    data = contest_mod.query_detail(adapter, name, _query_context(
        adapter, root, item_id, token=token, server_host=server_host))
    return {"name": name, "item_id": item_id, "data": data}


@app.get("/api/contests/{cid}/questions")
def contest_questions(cid: str, token: str = "", server_host: str = ""):
    """从平台拉取题目列表; 拉取成功后保存 token, 并标注每题本地是否已导入。"""
    _require_api_auto()
    root = store.get_root() or ""
    adapter = contest_mod.load_adapter(cid)
    token = token.strip() or store.get_contest_token(cid, root)
    host = _contest_host(adapter, root, server_host)
    if not token:
        raise HTTPException(400, "未提供队伍 token")
    # 列表先独立返回；羊城杯详情接口有限流，不能因单题详情失败拖垮整批查询。
    questions = contest_mod.fetch_questions(
        adapter, token, host, include_details=False)
    store.set_contest_token(cid, token, root)
    if host:
        store.set_contest_host(cid, root, host)

    bound: dict[str, dict] = {}
    root = store.get_root()
    if root:
        for ch in store.list_challenges(root):
            c = ch.contest or {}
            if c.get("adapter") == cid and c.get("question_id"):
                bound[str(c["question_id"])] = {
                    "id": ch.id, "name": ch.name, "status": ch.status, "flag": ch.flag,
                }
    for q in questions:
        q["local"] = bound.get(str(q["question_id"]))
    return {"contest": contest_mod.adapter_summary(adapter), "questions": questions}


@app.post("/api/contests/{cid}/import", status_code=201)
async def import_questions(cid: str, body: ImportIn):
    """把平台题目批量导入为本地题目 (去重: 同 question_id 已存在则跳过)。"""
    root = store.get_root()
    if not root:
        raise HTTPException(400, "未设置根目录")
    _require_api_auto(root)
    adapter = contest_mod.load_adapter(cid)
    token = store.get_contest_token(cid, root)
    host = _contest_host(adapter, root)
    if not token:
        raise HTTPException(400, "未保存 token, 请先拉取一次题目")

    questions = {str(q["question_id"]): q for q in contest_mod.fetch_questions(
        adapter, token, host, include_details=False)}
    existing = {
        str((ch.contest or {}).get("question_id")): ch
        for ch in store.list_challenges(root)
        if (ch.contest or {}).get("adapter") == cid
    }
    created, skipped, errors = [], [], []
    for raw_qid in body.question_ids:
        qid = str(raw_qid)
        q = questions.get(qid)
        if q is None:
            errors.append(f"{qid}: 平台列表中不存在")
            continue
        if qid in existing:
            skipped.append({"question_id": qid, "name": existing[qid].name})
            continue
        try:
            # 只请求本次勾选题的详情，避免整批导入前被平台限流全部拒绝。
            q = await asyncio.to_thread(
                contest_mod.fetch_question_detail, adapter, q, token, host)
            kw = contest_mod.import_payload(adapter, q)
            binding = kw.pop("contest")
            h = (body.harnesses.get(qid) or body.harness
                 or CONFIG.get("default_harness", "codex"))
            ch = store.create_challenge(root, harness=h, harnesses=[h], **kw)
            ch.contest = binding
            if q.get("is_solved"):
                ch.note = "平台显示该题已解出"
            if ch.attachment_urls:
                ch.status = "downloading"
                ch.save()
                _download_tasks[ch.id] = asyncio.create_task(
                    asyncio.to_thread(downloader.download_all, ch, CONFIG))
            else:
                ch.status = "ready"
                ch.save()
            if body.auto_launch:
                _mark_launching(ch)
                _spawn_bg(_launch(ch))
                ch = store.Challenge.load(ch.meta_path)
            created.append({"id": ch.id, "name": ch.name, "question_id": qid})
        except Exception as e:  # 批量导入单题失败不拖垮整批
            errors.append(f"{q.get('title') or qid}: {e}")
    return {"created": created, "skipped": skipped, "errors": errors}


def _apply_platform_target(ch: store.Challenge, target: str) -> int:
    ch.target = target
    ch.supplements.append({"ts": time.time(),
                           "text": f"【平台环境已就绪】靶机地址：{target}"})
    ch.save()
    try:
        prompts.write_prompt_file(ch)
    except OSError:
        pass
    sent = 0
    msg = f"【平台环境已就绪】靶机地址：{target}。请基于该环境继续解题。"
    for unit in _message_units(ch):
        tmuxctl.send_text(unit["tmux"]["pane"], msg)
        sent += 1
    return sent


@app.post("/api/contests/{cid}/questions/{qid}/reset")
async def contest_reset(cid: str, qid: str):
    """重置平台容器环境 (仅容器题支持)。"""
    _require_api_auto()
    root = store.get_root() or ""
    adapter = contest_mod.load_adapter(cid)
    token = store.get_contest_token(cid, root)
    host = _contest_host(adapter, root)
    if not token:
        raise HTTPException(400, "未保存 token, 请先在「赛事平台」拉取一次题目")
    result = contest_mod.reset_env(adapter, token, qid, host)
    if result.get("target"):
        for ch in store.list_challenges(root):
            binding = ch.contest or {}
            if (binding.get("adapter") == cid
                    and str(binding.get("question_id")) == str(qid)):
                result["challenge_id"] = ch.id
                result["notified"] = await asyncio.to_thread(
                    _apply_platform_target, ch, result["target"])
                break
    return result


@app.post("/api/challenges/{cid}/submit_flag")
def submit_flag(cid: str, body: FlagIn):
    """把 flag 提交到题目绑定的赛事平台; 平台判对才本地落盘并标 solved。"""
    ch = _get(cid)
    binding = ch.contest or {}
    if not binding.get("question_id"):
        raise HTTPException(400, "该题未绑定赛事平台(非平台导入), 无法提交")
    _require_api_auto(ch.root)
    adapter = contest_mod.load_adapter(binding.get("adapter") or "")
    token = store.get_contest_token(adapter["id"], ch.root)
    host = _contest_host(adapter, ch.root)
    if not token:
        raise HTTPException(400, "未保存平台 token, 请先在「赛事平台」拉取一次题目")
    flag = body.flag.strip()
    if not flag:
        raise HTTPException(400, "flag 为空")
    result = contest_mod.submit_answer(adapter, token, binding["question_id"], flag, host)
    if result["ok"]:
        if body.attempt and body.attempt not in {a.get("id") for a in ch.attempts}:
            raise HTTPException(400, f"未知 attempt: {body.attempt}")
        ch.flag = flag
        ch.flag_candidate = ""
        ch.flag_attempt = body.attempt
        ch.status = "solved"
        ch.save()
        if body.stop_others:
            _stop_group_after_solve(ch)
    result["saved"] = bool(result["ok"])
    return result


# ---------------------------------------------------------------- launch pipeline

def _unit_lock(ch: store.Challenge, unit: dict) -> asyncio.Lock:
    key = f"{ch.meta_path}:{unit.get('id') or 'legacy'}"
    return _unit_locks.setdefault(key, asyncio.Lock())


def _resource_config() -> dict:
    return CONFIG.get("resource_limits") or {}


def _slice_memory_high() -> str:
    cfg = _resource_config()
    explicit = str(cfg.get("slice_memory_high") or "").strip()
    if explicit:
        return explicit
    ratio = min(0.95, max(0.1, float(cfg.get("slice_memory_ratio", 0.8))))
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            total_kib = int(line.split()[1])
            return str(int(total_kib * ratio * 1024))
    raise OSError("无法读取 MemTotal")


def _slice_memory_display() -> str:
    explicit = str(_resource_config().get("slice_memory_high") or "").strip()
    if explicit:
        return explicit
    return f"{int(_slice_memory_high()) / 1024 ** 3:.1f}G"


def _probe_resource_limits() -> None:
    global _resource_limits_supported
    _resource_limits_supported = False
    cfg = _resource_config()
    slice_name = cfg.get("slice_name", "ubz-ctf.slice")
    if not cfg.get("enabled") or not cfg.get("scope_enabled", False):
        # 清除旧版本留下的运行时限制：已运行任务只保留启动闸门，不再限流。
        if shutil.which("systemctl"):
            try:
                subprocess.run(
                    ["systemctl", "--user", "--runtime", "set-property", slice_name,
                     "CPUQuota=", "MemoryHigh="],
                    capture_output=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass
        return
    if not shutil.which("systemd-run"):
        return
    quota = int(cfg.get("slice_cpu_quota", 0))
    memory = _slice_memory_high()
    cpu_property = f"CPUQuota={quota}%" if quota > 0 else "CPUQuota="
    try:
        # 只写运行时 slice 属性，不落盘、不改 harness；总量共享而非每路限额。
        configured = subprocess.run(
            ["systemctl", "--user", "--runtime", "set-property", slice_name,
             cpu_property, f"MemoryHigh={memory}"],
            capture_output=True, timeout=10)
        if configured.returncode != 0:
            raise OSError(configured.stderr.decode(errors="replace").strip())
        probe = subprocess.run(
            ["systemd-run", "--user", "--scope", "--quiet", "--collect",
             "--slice", slice_name, "--", "/bin/true"],
            capture_output=True, timeout=10)
        _resource_limits_supported = probe.returncode == 0
    except (OSError, subprocess.SubprocessError):
        _resource_limits_supported = False
    if not _resource_limits_supported:
        logger.warning("systemd slice 不可用，harness 将以普通方式启动（不做配置修改）")


def _admission_status() -> tuple[bool, str]:
    cfg = _resource_config()
    if not cfg.get("enabled") or not cfg.get("admission_control"):
        return True, ""
    try:
        available_mb = 0
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                available_mb = int(line.split()[1]) // 1024
                break
        minimum = int(cfg.get("min_available_mb", 1800))
        if available_mb and available_mb < minimum:
            return False, f"可用内存 {available_mb}MB < 启动阈值 {minimum}MB"
        load1 = float(Path("/proc/loadavg").read_text().split()[0])
        per_cpu = load1 / max(1, os.cpu_count() or 1)
        maximum = float(cfg.get("max_load_per_cpu", 1.5))
        if per_cpu > maximum:
            return False, f"每核负载 {per_cpu:.2f} > 启动阈值 {maximum:.2f}"
    except (OSError, ValueError):
        return True, ""   # 读不到系统指标时不把启动卡死
    return True, ""


async def _wait_for_resources() -> None:
    global _resource_gate_reason
    while True:
        allowed, reason = await asyncio.to_thread(_admission_status)
        if allowed:
            _resource_gate_reason = ""
            return
        _resource_gate_reason = reason
        await asyncio.sleep(5)


def _resource_limited_command(ch: store.Challenge, unit: dict, cmd: str) -> str:
    """只在外层加 systemd scope，原 harness 命令与配置保持原样。"""
    cfg = _resource_config()
    if not cfg.get("enabled") or not cfg.get("scope_enabled", False) \
            or not _resource_limits_supported:
        return cmd
    scope = "ubz-" + (unit.get("tmux", {}).get("ubz_id") or "attempt")[:16]
    slice_name = cfg.get("slice_name", "ubz-ctf.slice")
    argv = ["systemd-run", "--user", "--scope", "--quiet", "--collect",
            "--unit", scope, "--slice", slice_name,
            "--", "bash", "-lc", cmd]
    return shlex.join(argv)


def _launch_limiter() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    limiter = _launch_limiters.get(loop)
    if limiter is None:
        limit = max(1, int(CONFIG.get("launch_concurrency", 2)))
        limiter = _launch_limiters[loop] = asyncio.Semaphore(limit)
    return limiter


@asynccontextmanager
async def _launch_slot():
    global _launch_waiting, _launch_active
    _launch_waiting += 1
    acquired = False
    try:
        await _wait_for_resources()
        async with _launch_limiter():
            _launch_waiting -= 1
            _launch_active += 1
            acquired = True
            try:
                yield
            finally:
                _launch_active -= 1
    finally:
        if not acquired:
            _launch_waiting -= 1


def _fresh_running_unit(ch: store.Challenge, unit: dict) -> dict | None:
    """锁内核对磁盘最新状态，覆盖并发请求各自持有旧 meta 副本的情况。"""
    latest = ch
    if ch.meta_path.is_file():
        try:
            latest = store.Challenge.load(ch.meta_path)
        except (OSError, ValueError, TypeError):
            latest = ch
    try:
        fresh = store.find_unit(latest, unit.get("id", ""))
    except ValueError:
        fresh = unit
    if fresh.get("status") not in ("running", "need_help"):
        return None
    return fresh if _unit_pane_exists(latest, fresh) else None


def _ensure_unit_identity(ch: store.Challenge, unit: dict) -> str:
    """attempt 的稳定身份；写进 meta 与 tmux @ubz_id，恢复时保持不变。"""
    tm = unit.setdefault("tmux", {})
    uid = tm.get("ubz_id", "")
    if not uid:
        uid = uuid.uuid4().hex
        tm["ubz_id"] = uid
    return uid


def _unit_pane_exists(ch: store.Challenge, unit: dict) -> bool:
    tm = unit.get("tmux", {})
    session = tm.get("session", "") or ch.tmux.get("session", "")
    return tmuxctl.pane_exists(
        tm.get("pane", ""), session, tm.get("ubz_id", ""))


def _kill_unit_pane(ch: store.Challenge, unit: dict) -> None:
    tm = unit.get("tmux", {})
    pane = tm.get("pane", "")
    if pane:
        session = tm.get("session", "") or ch.tmux.get("session", "")
        tmuxctl.kill_pane(pane, session=session,
                          ubz_id=tm.get("ubz_id", ""))


def _path_within(path: str, workdir: str) -> bool:
    try:
        Path(path).resolve().relative_to(Path(workdir).resolve())
        return bool(path and workdir)
    except (OSError, ValueError):
        return False


def _migrate_competition_modes() -> None:
    """把旧根目录的模式推断一次并落盘，之后只响应用户显式切换。"""
    state = store.list_roots()
    for item in state["recent_roots"]:
        if item["exists"]:
            store.set_competition_mode(item["path"], item["competition_mode"])


def _migrate_root_session(root: str, challenges: list[store.Challenge],
                          states: dict[str, tmuxctl.PaneState]) -> str:
    """安全时把旧 basename session 改名为带哈希的新名，返回旧名。"""
    expected = store.session_name_for_root(root)
    legacy = store._legacy_session_name_for_root(root)
    used = {ch.tmux.get("session", "") for ch in challenges}
    for ch in challenges:
        used.update(a.get("tmux", {}).get("session", "") for a in ch.attempts)
    used.discard("")
    if expected in used or used - {expected} != {legacy}:
        return ""
    if tmuxctl.has_session(expected):
        return ""   # 两个 session 都已存在时不自动合并，保留原状最稳妥
    if tmuxctl.has_session(legacy):
        tmuxctl.rename_session(legacy, expected)
    # 旧 session 不存在（例如 VM 重启后）也只需更新 meta，不必创建它。
    for pane, cur in list(states.items()):
        if cur.session == legacy:
            states[pane] = cur._replace(session=expected)
    return legacy


def _migrate_tmux_identities() -> dict[str, int]:
    """为旧 meta 补 UUID；仅按 session+cwd 安全认领跑着的无标签 pane。

    %pane_id 在 tmux/VM 重启后会被无关进程复用，绝不能仅凭旧 ID 接管。
    无法确认归属的旧 pane 留给 monitor 标 pane_gone，用户恢复时分配新 pane。
    """
    states = tmuxctl.pane_states()
    state = store.list_roots()
    roots = [state["current_root"]] if state["current_root"] else []
    roots += [r["path"] for r in state["recent_roots"] if r["exists"]]
    seen_roots: set[str] = set()
    claimed: set[str] = set()
    stats = {"units": 0, "new_ids": 0, "adopted": 0}
    for root in roots:
        if not root or root in seen_roots:
            continue
        seen_roots.add(root)
        challenges = store.list_challenges(root)
        legacy_session = _migrate_root_session(root, challenges, states)
        expected_session = store.session_name_for_root(root)
        for ch in challenges:
            dirty = False
            if legacy_session and ch.tmux.get("session") == legacy_session:
                ch.tmux["session"] = expected_session
                dirty = True
            try:
                store.ensure_collab_files(ch)   # 旧会话也能读到绝对路径兜底
            except OSError:
                pass
            for unit in store.unit_views(ch):
                if legacy_session and unit["tmux"].get("session") == legacy_session:
                    unit["tmux"]["session"] = expected_session
                    dirty = True
                stats["units"] += 1
                tm = unit["tmux"]
                if not tm.get("ubz_id"):
                    tm["ubz_id"] = uuid.uuid4().hex
                    stats["new_ids"] += 1
                    dirty = True
                uid = tm["ubz_id"]
                pane = tm.get("pane", "")
                session = tm.get("session", "") or ch.tmux.get("session", "")
                cur = states.get(pane) if pane else None
                if cur is None or cur.session != session:
                    continue
                if cur.ubz_id == uid:
                    claimed.add(pane)
                    if tm.get("window") != cur.window:
                        tm["window"] = cur.window
                        dirty = True
                    continue
                # 旧版本没有标签：只有 cwd 能证明归属且未被别路认领才补标。
                if (not cur.ubz_id and pane not in claimed
                        and _path_within(cur.path, unit.get("workdir", ch.workdir))):
                    try:
                        tmuxctl.tag_pane(pane, uid)
                    except tmuxctl.TmuxError:
                        continue
                    states[pane] = cur._replace(ubz_id=uid)
                    claimed.add(pane)
                    stats["adopted"] += 1
                    tm["window"] = cur.window
                    dirty = True
            if dirty:
                store.apply_unit(ch, unit)
                try:
                    ch.save()
                except OSError:
                    pass
    return stats


def _unit_env_command(ch: store.Challenge, unit: dict, uid: str) -> str:
    """首次启动与恢复共用环境，Skills 也能定位工具、黑板和工作目录。"""
    assignments = [
        f"UBZ_HARNESS={shlex.quote(unit.get('harness', ''))}",
        f"UBZ_INSTANCE_ID={shlex.quote(uid)}",
        f"UBZ_WORKDIR={shlex.quote(unit['workdir'])}",
        f"UBZ_CHALLENGE_DIR={shlex.quote(ch.workdir)}",
        f"UBZ_BOARD_BIN={shlex.quote(str(PROJECT_DIR / 'bin' / 'ubz-board'))}",
        f"UBZ_BOARD_FILE={shlex.quote(str(Path(ch.workdir) / 'board.md'))}",
    ]
    if unit.get("port_base"):
        assignments = [
            f"UBZ_PORT_BASE={unit['port_base']}",
            f"UBZ_PORT_END={unit['port_base'] + 999}",
            *assignments,
        ]
    bin_dir = str(PROJECT_DIR / "bin")
    return "export " + " ".join(assignments) + f' PATH="{bin_dir}:$PATH"'


def _win_name(ch: store.Challenge, unit: dict) -> str:
    """pane 标题: 旧版单路=题目名; 多开=题目名·harness, 防御路再挂个"防",
    终端里一眼区分是哪一路。"""
    if unit.get("_legacy"):
        return ch.name
    role_mark = "·防" if unit.get("role") == "defense" else ""
    return f"{ch.name}·{unit['harness']}{role_mark}"


def _attempt_prompt(ch: store.Challenge, unit: dict) -> str:
    """该路的注入文本: 按该路自己的 cwd 渲染 prompt.md 并写盘
    (多开的路 cwd 是 runs/<h>/, 附件是实体拷贝、黑板是符号链接; 末尾追加协作指针)。
    防御路(role=defense)改用防御模板渲染: 交付物是补丁, 页脚不提 flag.txt。
    旧版单路维持原行为: 主目录 prompt.md, 无纪律后缀。
    协作指针只在真的多路(>=2 attempts)时追加, 单路题不误导唯一的 agent;
    例外是 AWDP 攻击路: 单路也给单路版指针 + 漏洞点接力说明 (防御路会自动加入)。
    黑板已有内容时点一句先读板接力; 该路的附加指令(directive)拼在最后。"""
    if unit.get("_legacy"):
        return prompts.write_prompt_file(ch).read_text(encoding="utf-8")
    ach = dataclasses.replace(ch, workdir=unit["workdir"])
    if unit.get("role") == "defense":
        text = prompts.render_defense_for(ach)
    else:
        text = prompts.render_for(ach)
    if len(ch.attempts) >= 2:
        text += prompts.attempt_suffix(unit["port_base"],
                                       board_entries=_board_entry_count(ch))
    elif ch.awdp and unit.get("role") != "defense":
        # AWDP 单攻击路: 防御路未开, 但黑板/纪律文件已落地, 端口段照发
        text += prompts.awdp_solo_suffix(unit["port_base"])
    else:
        # 普通单路也给黑板接力记录与端口段指针, 确保后续点 +加开 时黑板已有积累
        text += prompts.solo_suffix(unit["port_base"],
                                    board_entries=_board_entry_count(ch))
    if ch.awdp and unit.get("role") != "defense":
        # 漏洞点接力: 攻击路一验证就写板, 系统自动开/喂防御路
        text += prompts.AWDP_RELAY_SUFFIX
    if unit.get("directive"):
        text += f"\n\n———\n该路附加指令：{unit['directive']}"
    (Path(unit["workdir"]) / "prompt.md").write_text(text, encoding="utf-8")
    return text


def _board_entry_count(ch: store.Challenge) -> int:
    """共享黑板当前条目数 (- 开头的行), 供注入时点"先读板"; 空板/无板为 0。"""
    try:
        return sum(1 for l in (Path(ch.workdir) / "board.md")
                   .read_text(encoding="utf-8").splitlines()
                   if l.lstrip().startswith("- "))
    except OSError:
        return 0


async def _auto_defense_trigger(cid: str, lines: list[str],
                                baseline: list[str] | None = None) -> None:
    """AWDP 漏洞点接力 (monitor 发现漏洞点条目数增长且过冷却时回调):
    - 先过 Jev 语义闸门 (config jev_vuln_gate): 纯改写/补充/合并不推;
      Jev 不可用回退全推 (冷却期兜底防刷屏)
    - 已有在跑的防御路 -> 把全量清单定向推给它 (不广播, 不打扰攻击路);
      防御路纪律是修一个验一个, 修完重打修补包
    - 没有 -> 按题目 defense_harness (空则 config defense_harness/default_harness)
      自动加开防御路, directive 带上漏洞点原文, 直奔这个洞修, 不从零审计。
    攻击路全程不停, 继续写完整 exp。"""
    ch = store.find_challenge(cid)
    if ch is None or not ch.awdp or not ch.auto_defense or not lines:
        return
    candidates = [l for l in lines if l not in (baseline or [])] or lines
    filtered = await asyncio.to_thread(
        jevgate.filter_new_vulns, CONFIG, baseline or [], candidates)
    if filtered is not None:
        if not filtered:
            return   # Jev 判定全是改写/补充/合并, 不打扰防御路
        lines = filtered
    alive = [a for a in ch.attempts
             if a.get("role") == "defense"
             and a.get("status") in ("launching", "running", "need_help")
             and _unit_pane_exists(ch, a)]
    if alive:
        await asyncio.to_thread(
            tmuxctl.send_text, alive[0]["tmux"]["pane"],
            "黑板 ## 漏洞点 有新增条目，当前全量清单如下"
            "（已修过的忽略，没修的排进修补队列；修一个验一个，"
            "每修完一个重打修补包并写板）：\n"
            + "\n".join(lines))
        return
    name = (ch.defense_harness or CONFIG.get("defense_harness")
            or CONFIG.get("default_harness", "codex"))
    try:
        harness.launch_command(CONFIG, name)
    except ValueError:
        return   # 配置的 harness 已不存在, 不自动开; 卡片上漏洞点计数可见, 人工加开
    att = store.add_attempt(
        ch, name, role="defense",
        directive="优先修补板上已验证漏洞点（条目里带复现依据；修一个验一个）：\n"
                  + "\n".join(lines))
    att["note"] = "自动加开：漏洞点接力"
    ch.save()
    await _launch_attempt(ch, att)


def _save_unit_state(ch: store.Challenge, unit: dict) -> None:
    """并发错峰/慢启动期间磁盘 meta 可能已被其它路或 PATCH 更新, 先重读再合并该路状态。"""
    store.apply_unit(ch, unit)
    if ch.meta_path.is_file() and not unit.get("_legacy"):
        try:
            latest = store.Challenge.load(ch.meta_path)
            for i, a in enumerate(latest.attempts):
                if a.get("id") == unit.get("id"):
                    if not unit.get("last_output") and a.get("last_output"):
                        unit["last_output"] = a["last_output"]
                    latest.attempts[i] = unit
                    break
            latest.status = store.aggregate_status(latest)
            latest.save()
            ch.status = latest.status
            return
        except Exception:
            pass
    ch.status = store.aggregate_status(ch)
    ch.save()


def _mark_launching(ch: store.Challenge) -> None:
    """先把待启动的路标为 launching 落盘, 让前端卡片立即反馈启动中状态。"""
    for u in store.unit_views(ch):
        if not u["tmux"].get("pane") or u["status"] in ("ready", "failed"):
            u["status"] = "launching"
            store.apply_unit(ch, u)
    ch.status = store.aggregate_status(ch)
    ch.save()


def _record_background_error(label: str, exc: Exception) -> None:
    global _background_errors, _background_last_error
    global _background_last_error_at, _background_last_log
    _background_errors += 1
    _background_last_error = f"{label}: {type(exc).__name__}: {exc}"
    _background_last_error_at = time.time()
    now = time.time()
    if now - _background_last_log >= 60:
        _background_last_log = now
        logger.exception("后台任务失败（60s 内同类后续错误仅计数）: %s", label)


def _spawn_bg(coro) -> asyncio.Task:
    """后台异步执行启动协程；异常限频记录并写入 health，不再静默吞掉。"""
    async def _runner():
        try:
            await coro
        except Exception as exc:
            _record_background_error("launch", exc)
    return asyncio.create_task(_runner())


async def _launch_attempt(ch: store.Challenge, att: dict,
                          stagger: float = 0.0) -> None:
    async with _unit_lock(ch, att):
        fresh = await asyncio.to_thread(_fresh_running_unit, ch, att)
        if fresh is not None:
            att["status"] = fresh["status"]
            att["tmux"].update(fresh["tmux"])
            return   # 重复 launch：已经在跑，不再开第二份进程
        async with _launch_slot():
            await _launch_attempt_locked(ch, att, stagger)


async def _launch_attempt_locked(ch: store.Challenge, att: dict,
                                 stagger: float = 0.0) -> None:
    """启动一路: (错开等待 ->) 开 pane 立即落盘 -> 起 harness -> 等就绪后注入提示词。
    开完 pane 立即落盘 pane_id, 确保慢启动期间卡片即可实时捕获加载画面与弹出终端。"""
    if stagger > 0:
        await asyncio.sleep(stagger)
    store.ensure_collab_files(ch)
    uid = _ensure_unit_identity(ch, att)
    att["status"] = "launching"
    _save_unit_state(ch, att)

    def _alloc_and_start() -> dict[str, str]:
        store.sync_attempt_attachments(ch)   # 附件实体拷进该路目录(IDA 等工具不能共享同一文件)
        tm = tmuxctl.allocate_pane(
            ch.tmux["session"], _win_name(ch, att), att["workdir"],
            int(CONFIG.get("panes_per_window", 4)), ubz_id=uid)
        tmuxctl.send_command(tm["pane"], _unit_env_command(ch, att, uid))
        cmd = harness.launch_command(CONFIG, att["harness"])
        cmd = _resource_limited_command(ch, att, cmd)
        tmuxctl.launch_harness(tm["pane"], cmd)
        return tm

    def _wait_and_inject(pane: str) -> None:
        harness.wait_ready(pane, att["harness"])
        # 慢启动等待期间用户可能已补充 target/info, 注入前优先读最新 meta 渲染提示词
        fresh_ch = ch
        if ch.meta_path.is_file():
            try:
                fresh_ch = store.Challenge.load(ch.meta_path)
            except Exception:
                fresh_ch = ch
        tmuxctl.send_text(pane, _attempt_prompt(fresh_ch, att))

    try:
        tm = await asyncio.to_thread(_alloc_and_start)
        att["tmux"].update(tm)
        att["exit_seen"] = 0   # 新 pane 无任何历史退出标记
        _save_unit_state(ch, att)
        await asyncio.to_thread(_wait_and_inject, tm["pane"])
        att["prompt_sent"] = True
        att["status"] = "running"
    except (tmuxctl.TmuxError, ValueError, OSError) as e:
        att["status"] = "failed"
        att["note"] = f"启动失败: {e}"
    _save_unit_state(ch, att)
    if att["status"] == "failed":
        raise HTTPException(500, f"{att['harness']} 启动失败: {att['note']}")


async def _launch(ch: store.Challenge) -> None:
    """等附件下载完 -> 渲染 prompt -> 并发错开启动所有未启动的路。"""
    task = _download_tasks.pop(ch.id, None)
    if task is not None:
        try:
            await asyncio.wait_for(task, timeout=180)
        except asyncio.TimeoutError:
            _cancel_download(ch.id)
            raise HTTPException(504, "附件下载超时(180s), 请稍后手动 launch")
        except (asyncio.CancelledError, downloader.DownloadCancelled):
            return   # 删除/显式取消后不得继续启动或重建 meta
        finally:
            _download_cancel.pop(ch.id, None)
        ch = store.Challenge.load(ch.meta_path)  # 下载线程已更新 meta

    try:
        prompts.write_prompt_file(ch)   # 主目录留一份模板底稿(各路的在 runs/<h>/)
        units = store.unit_views(ch)
        pending = [u for u in units
                   if not u["tmux"].get("pane")
                   or u["status"] in ("ready", "launching", "failed")]
        results = await asyncio.gather(
            *(_launch_attempt(ch, u, stagger=i * 1.0)
              for i, u in enumerate(pending)),
            return_exceptions=True)
        ch = store.Challenge.load(ch.meta_path)
        ch.status = store.aggregate_status(ch)
        ch.save()
        failures = [r for r in results if isinstance(r, Exception)]
        if failures and len(failures) == len(pending):
            raise HTTPException(500, f"全部启动失败: {failures[0]}")
    except (tmuxctl.TmuxError, ValueError, OSError) as e:
        ch.status = "failed"
        ch.note = f"启动失败: {e}"
        ch.save()
        raise HTTPException(500, f"启动失败: {e}")


def _get(cid: str) -> store.Challenge:
    ch = store.find_challenge(cid)
    if ch is None:
        raise HTTPException(404, f"题目不存在: {cid}")
    return ch


def _status_without_flag(ch: store.Challenge) -> str:
    """Infer the challenge status after its confirmed flag is cleared."""
    saw_pane = False
    for unit in store.unit_views(ch):
        pane = unit["tmux"].get("pane", "")
        if not pane:
            continue
        if not _unit_pane_exists(ch, unit):
            return "pane_gone"
        saw_pane = True
        current = tmuxctl.pane_current_command(pane)
        if current and current not in tmuxctl.SHELL_CMDS:
            return "running"
    return "exited" if saw_pane else "ready"


# ---------------------------------------------------------------- static

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(PROJECT_DIR / "web" / "index.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8600)
