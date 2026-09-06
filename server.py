"""ubz-ctf: FastAPI 服务端。

启动: uvicorn server:app --host 127.0.0.1 --port 8600
(或直接 python server.py, 见文件末尾)
"""

from __future__ import annotations

import asyncio
import shutil
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from core import downloader, harness, monitor, prompts, store, tmuxctl

PROJECT_DIR = Path(__file__).resolve().parent
CONFIG = store.load_config()
MONITOR = monitor.Monitor(CONFIG)

# 进行中的下载任务: challenge_id -> asyncio.Task
_download_tasks: dict[str, asyncio.Task] = {}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    MONITOR.start()
    yield
    await MONITOR.stop()


app = FastAPI(title="ubz-ctf", lifespan=lifespan)


# ---------------------------------------------------------------- models

class RootIn(BaseModel):
    path: str
    create_if_missing: bool = False


class ChallengeIn(BaseModel):
    name: str
    category: str
    info: str = ""
    target: str = ""
    attachment_urls: list[str] = []
    harness: str = ""
    custom_prompt: str = ""
    auto_launch: bool = True


class MessageIn(BaseModel):
    text: str


class FlagIn(BaseModel):
    flag: str


class StatusIn(BaseModel):
    status: str
    note: str = ""


class PatchIn(BaseModel):
    """补充/修改题目信息。message 非空则同时发送到 pane。"""
    target: str | None = None
    info: str | None = None
    message: str = ""


# ---------------------------------------------------------------- settings

@app.get("/api/config")
def get_config():
    return {
        "harnesses": harness.harness_names(CONFIG),
        "default_harness": CONFIG.get("default_harness", "codex"),
        "categories": prompts.categories(),
        "terminal_emulator": CONFIG.get("terminal_emulator"),
    }


@app.get("/api/settings/root")
def get_root():
    return store.list_roots()


@app.put("/api/settings/root")
def put_root(body: RootIn):
    try:
        root = store.set_root(body.path, create=body.create_if_missing)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"current_root": root,
            "tmux_session": store.session_name_for_root(root)}


@app.get("/api/templates")
def get_templates():
    return prompts.list_templates()


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
    return {"saved": saved, "errors": errors}


# ---------------------------------------------------------------- challenges

@app.get("/api/challenges")
def list_challenges():
    root = store.get_root()
    if not root:
        return {"root": None, "challenges": []}
    return {
        "root": root,
        "tmux_session": store.session_name_for_root(root),
        "elsewhere_running": MONITOR.elsewhere_running,
        "challenges": [vars(c) for c in store.list_challenges(root)],
    }


@app.post("/api/challenges", status_code=201)
async def create_challenge(body: ChallengeIn):
    root = store.get_root()
    if not root:
        raise HTTPException(400, "未设置根目录, 请先 PUT /api/settings/root")
    if body.category != "custom" and body.category not in prompts.list_templates():
        raise HTTPException(400, f"未知类型: {body.category}")
    if body.category == "custom" and not body.custom_prompt.strip():
        raise HTTPException(400, "custom 类型必须填写自定义提示词")

    ch = store.create_challenge(
        root, name=body.name, category=body.category, info=body.info,
        target=body.target, attachment_urls=body.attachment_urls,
        harness=body.harness or CONFIG.get("default_harness", "codex"),
        custom_prompt=body.custom_prompt)

    if ch.attachment_urls:
        ch.status = "downloading"
        ch.save()
        _download_tasks[ch.id] = asyncio.create_task(
            asyncio.to_thread(downloader.download_all, ch, CONFIG))
    else:
        ch.status = "ready"
        ch.save()

    if body.auto_launch:
        await _launch(ch)
    return vars(store.Challenge.load(ch.meta_path))


@app.get("/api/challenges/{cid}")
def get_challenge(cid: str):
    return vars(_get(cid))


@app.post("/api/challenges/{cid}/launch")
async def launch(cid: str):
    ch = _get(cid)
    await _launch(ch)
    return vars(store.Challenge.load(ch.meta_path))


@app.post("/api/challenges/{cid}/resume")
async def resume(cid: str):
    """真正的恢复: resume 命令恢复会话 -> 处理弹窗 -> 无 goal 自动续跑时发续跑指令。
    提示词从未送达过(如启动即失败)则全新启动+注入。"""
    ch = _get(cid)
    fresh_start = not ch.prompt_sent
    cmd = (harness.launch_command if fresh_start
           else harness.resume_command)(CONFIG, ch.harness)
    pane = ch.tmux.get("pane", "")
    try:
        if pane and tmuxctl.pane_exists(pane):
            # 先记基线再发命令: 命令发出后 harness 可能秒退, 之后再记就把新退出吞了
            ch.exit_seen = tmuxctl.exit_mark_count(pane)
            tmuxctl.send_command(pane, f"{cmd}; echo {tmuxctl.EXIT_MARK}$?")
            tmuxctl.wait_harness_ready(pane)
        else:
            tm = await asyncio.to_thread(
                tmuxctl.allocate_pane, ch.tmux["session"], ch.name,
                ch.workdir, int(CONFIG.get("panes_per_window", 4)))
            ch.tmux.update(tm)
            pane = tm["pane"]
            tmuxctl.launch_harness(pane, cmd)
            tmuxctl.wait_harness_ready(pane)
            ch.exit_seen = 0
        if fresh_start:
            prompt_file = prompts.write_prompt_file(ch)
            tmuxctl.send_text(pane, prompt_file.read_text(encoding="utf-8"))
            ch.prompt_sent = True
        else:
            # 关键一步: 恢复会话只是回到输入框, 推一下才真正继续解题
            await asyncio.to_thread(harness.nudge_to_continue, pane, ch.harness)
        ch.status = "running"
        ch.save()
    except (tmuxctl.TmuxError, ValueError, OSError) as e:
        raise HTTPException(500, str(e))
    return vars(ch)


@app.delete("/api/challenges/{cid}")
def delete_challenge(cid: str, files: bool = False):
    """删除题目: 杀掉 pane, 移除出面板。files=true 时连同题目目录一起删除。"""
    ch = _get(cid)
    task = _download_tasks.pop(cid, None)
    if task is not None:
        task.cancel()
    pane = ch.tmux.get("pane", "")
    if pane:
        tmuxctl.kill_pane(pane)
    if files:
        shutil.rmtree(ch.workdir, ignore_errors=True)
    else:
        Path(ch.meta_path).unlink(missing_ok=True)
    return {"ok": True, "files_deleted": files}


@app.post("/api/challenges/{cid}/message")
def send_message(cid: str, body: MessageIn):
    ch = _get(cid)
    pane = ch.tmux.get("pane", "")
    if not pane or not tmuxctl.pane_exists(pane):
        raise HTTPException(400, "pane 不存在, 无法发送")
    if not body.text.strip():
        raise HTTPException(400, "消息为空")
    cur = tmuxctl.pane_current_command(pane)
    if cur in tmuxctl.SHELL_CMDS:
        raise HTTPException(400, "agent 未在运行(pane 里是 shell), 消息未发送")
    tmuxctl.send_text(pane, body.text)
    return {"ok": True}


@app.patch("/api/challenges/{cid}")
def patch_challenge(cid: str, body: PatchIn):
    """补充靶机/更新题目信息; message 非空时同步通知 pane 里的 agent。"""
    ch = _get(cid)
    changed = False
    if body.target is not None and body.target.strip() != ch.target:
        ch.target = body.target.strip()
        changed = True
    if body.info is not None and body.info != ch.info:
        ch.info = body.info
        changed = True
    if changed:
        ch.save()
        try:
            prompts.write_prompt_file(ch)   # 磁盘记录同步为最新
        except OSError:
            pass
    if body.message.strip():
        pane = ch.tmux.get("pane", "")
        if not pane or not tmuxctl.pane_exists(pane):
            raise HTTPException(400, "信息已保存, 但 pane 不存在, 消息未发送")
        cur = tmuxctl.pane_current_command(pane)
        if cur in tmuxctl.SHELL_CMDS:
            raise HTTPException(400, "信息已保存, 但 agent 未在运行, 消息未发送")
        tmuxctl.send_text(pane, body.message)
        ch.supplements.append({"ts": time.time(), "text": body.message})
        ch.save()
    return vars(ch)


@app.post("/api/challenges/{cid}/focus")
def focus(cid: str):
    ch = _get(cid)
    if not ch.tmux.get("pane"):
        raise HTTPException(400, "题目尚未启动")
    try:
        msg = tmuxctl.spawn_terminal(
            CONFIG.get("terminal_emulator", "gnome-terminal"), ch.tmux)
    except tmuxctl.TmuxError as e:
        raise HTTPException(500, str(e))
    return {"ok": True, "message": msg}


@app.post("/api/challenges/{cid}/stop")
def stop(cid: str):
    ch = _get(cid)
    pane = ch.tmux.get("pane", "")
    if pane:
        tmuxctl.kill_pane(pane)
    ch.status = "stopped"
    ch.save()
    return vars(ch)


@app.post("/api/challenges/{cid}/flag")
def set_flag(cid: str, body: FlagIn):
    ch = _get(cid)
    ch.flag = body.flag.strip()
    if ch.flag:
        ch.flag_candidate = ""
        ch.status = "solved"
    elif ch.status == "solved":
        # `solved` is derived from a non-empty manually confirmed flag.  Do not
        # leave the challenge solved after that flag is removed; recover the
        # most accurate current state from its pane instead.
        ch.status = _status_without_flag(ch)
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


@app.get("/api/challenges/{cid}/output")
def get_output(cid: str, lines: int = 80):
    ch = _get(cid)
    pane = ch.tmux.get("pane", "")
    if not pane or not tmuxctl.pane_exists(pane):
        return {"output": ch.last_output, "live": False}
    try:
        return {"output": tmuxctl.capture(pane, lines=lines), "live": True}
    except tmuxctl.TmuxError as e:
        return {"output": "", "live": False, "error": str(e)}


# ---------------------------------------------------------------- launch pipeline

async def _launch(ch: store.Challenge) -> None:
    """等附件下载完 -> 渲染 prompt.md -> 开 pane -> 起 harness -> 注入提示词。"""
    task = _download_tasks.pop(ch.id, None)
    if task is not None:
        try:
            await asyncio.wait_for(task, timeout=180)
        except asyncio.TimeoutError:
            raise HTTPException(504, "附件下载超时(180s), 请稍后手动 launch")
        ch = store.Challenge.load(ch.meta_path)  # 下载线程已更新 meta

    try:
        prompts.write_prompt_file(ch)
        ch.status = "launching"
        ch.save()

        def _tmux_launch() -> dict[str, str]:
            tm = tmuxctl.allocate_pane(
                ch.tmux["session"], ch.name, ch.workdir,
                int(CONFIG.get("panes_per_window", 4)))
            cmd = harness.launch_command(CONFIG, ch.harness)
            tmuxctl.launch_harness(tm["pane"], cmd)
            tmuxctl.wait_harness_ready(tm["pane"])
            tmuxctl.send_text(tm["pane"],
                              (Path(ch.workdir) / "prompt.md").read_text(
                                  encoding="utf-8"))
            return tm

        tm = await asyncio.to_thread(_tmux_launch)
        ch.tmux.update(tm)
        ch.exit_seen = 0   # 新 pane 无任何历史退出标记
        ch.prompt_sent = True
        ch.status = "running"
        ch.save()
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
    pane = ch.tmux.get("pane", "")
    if not pane:
        return "ready"
    if not tmuxctl.pane_exists(pane):
        return "pane_gone"
    current = tmuxctl.pane_current_command(pane)
    if not current or current in tmuxctl.SHELL_CMDS:
        return "exited"
    return "running"


# ---------------------------------------------------------------- static

@app.get("/", include_in_schema=False)
def index():
    return FileResponse(PROJECT_DIR / "web" / "index.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8600)
