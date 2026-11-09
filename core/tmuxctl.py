"""ubz-ctf core: tmux CLI 封装。

关键机制:
  - 题目 = pane; panes_per_window<=0 时全部平铺在 session 唯一 window 里(一屏观察),
    >0 时每 window 这么多 pane, 满了开新 window
  - 提示词注入走 load-buffer + paste-buffer (bracketed paste), 多行中文不会提前提交;
    提交带确认: Enter 可能被慢启动 TUI 的首帧渲染吞掉, 看不到忙碌标志就补按
  - harness 退出标记: 启动命令后缀 `; echo UBZ-EXIT:$?`, monitor 捕获此标记判定退出
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
import uuid
from typing import NamedTuple

EXIT_MARK = "UBZ-EXIT:"

# 退出标记必须独占一行 (真退出时 shell 打印 "UBZ-EXIT:0"),
# 否则启动命令回显里的字面量 `echo UBZ-EXIT:$?` 会造成误判
EXIT_RE = re.compile(r"(?m)^" + re.escape(EXIT_MARK) + r"\d+\s*$")

# pane_current_command 为以下值时认为 harness 未在跑( pane 里只有 shell )
SHELL_CMDS = {"zsh", "bash", "sh", "fish", "dash", "tmux", "login"}

# harness 首次进入新目录时的信任确认弹窗: (标志文本, 按键序列)
# 注意各 TUI 默认项不同: codex/cursor/kimi/agy 默认 Yes 直接回车; claude 新版默认在 "No, exit",
# 必须先按 Down 移到 "Yes, I trust this folder" 再回车, 否则等于替它选退出!
DIALOG_RULES = (
    ("Is this a project you created or one you trust", ("Down", "Enter")),  # claude 新版
    # 分屏/长路径时顶部问题可能被裁出可见尾部，直接识别默认选中的 No；绝不能按成退出。
    ("❯ No, exit", ("Down", "Enter")),
    ("Do you trust the contents of this directory", ("Enter",)),            # codex / cursor
    ("Trust this workspace", ("Enter",)),                                   # cursor 边框垫底兜底
    ("Do you trust the files in this folder", ("Enter",)),                  # claude 旧版
    ("Trust this folder?", ("Enter",)),                                     # kimi-code
    ("Do you trust the contents of this project", ("Enter",)),              # agy
    ("Resume paused goal?", ("Enter",)),  # codex resume 后: 默认项即 "1. Resume goal"
)

# 提交确认用的忙碌标志: 各 TUI 的状态栏只在忙碌时绘制, 不会留在 scrollback。
# codex "Working ("/goal 模式 "Pursuing goal"; cursor "ctrl+c to stop";
# claude/dsh "esc to interrupt" (dsh 中文界面 "esc 中断" / "准备中…");
# opencode "esc interrupt";
# agy "esc to cancel" / "Generating..." / "Running command...";
# kimi 月相旋转指示器 "🌑 ·" .. "🌘 ·"
BUSY_MARKERS = (
    "Working (", "Pursuing goal", "ctrl+c to stop",
    "esc to interrupt", "esc interrupt", "esc 中断", "准备中…",
    "esc to cancel", "Generating...", "Running command...",
    "🌑 ·", "🌒 ·", "🌓 ·", "🌔 ·", "🌕 ·", "🌖 ·", "🌗 ·", "🌘 ·",
)

# claude 2.1 自定义 statusLine 时底栏不画 "esc to interrupt", 忙碌态只剩形如
# "* Undulating…" / "✢ Thinking…" 的单行省略号 spinner (完工后变为 "✻ Sautéed for 12s")
_CLAUDE_SPINNER_RE = re.compile(r"^\s*[·✢✳✶✻✽*]\s+\S+…")

# pi 1.5 的 Working 嵌在编辑器上边框: "── ⠦ Working ─────";
# regular 模式则是独立的 "⠦ Working" 行。不能匹配普通文本里的 Working。
_PI_BUSY_RE = re.compile(
    r"^\s*(?:──\s*)?[⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏]\s+"
    r"(?:Working|Retrying|Compacting context|Auto-compacting|Summarizing branch)\b"
)


def is_busy(lines: list[str] | str) -> bool:
    """判断可见尾部行是否处于忙碌状态 (兼容所有内置 TUI harness)。"""
    if isinstance(lines, str):
        lines = lines.splitlines()
    for line in lines:
        if any(m in line for m in BUSY_MARKERS):
            return True
        if _CLAUDE_SPINNER_RE.search(line) or _PI_BUSY_RE.search(line):
            return True
    return False


class TmuxError(RuntimeError):
    pass


def _run(args: list[str], input_text: str | None = None, check: bool = True) -> str:
    proc = subprocess.run(
        ["tmux", *args],
        input=input_text,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise TmuxError(f"tmux {' '.join(args)} 失败: {proc.stderr.strip()}")
    return proc.stdout


# ---------------------------------------------------------------- session/window/pane

def has_session(session: str) -> bool:
    proc = subprocess.run(["tmux", "has-session", "-t", session],
                          capture_output=True, text=True)
    return proc.returncode == 0


def ensure_session(session: str) -> None:
    if not has_session(session):
        # 显式尺寸: detached session 默认 80x24, 4 分屏会太小
        _run(["new-session", "-d", "-s", session, "-x", "220", "-y", "55"])


def rename_session(old: str, new: str) -> None:
    if old != new:
        _run(["rename-session", "-t", old, new])


def _windows(session: str) -> list[dict]:
    out = _run(["list-windows", "-t", session,
                "-F", "#{window_index}\t#{window_panes}"])
    wins = []
    for line in out.splitlines():
        if not line.strip():
            continue
        idx, panes = line.split("\t")
        wins.append({"index": idx, "panes": int(panes)})
    return wins


UBZ_PANE_OPTION = "@ubz_id"
_PANE_LIST_FORMAT = (
    "#{pane_id}\t#{session_name}\t#{window_index}\t"
    "#{pane_current_command}\t#{pane_current_path}\t#{@ubz_id}"
)


class PaneState(NamedTuple):
    session: str
    window: str
    command: str
    path: str
    ubz_id: str


def tag_pane(pane_id: str, ubz_id: str) -> None:
    """把稳定的 attempt UUID 写进 tmux 服务端，防止 %pane_id 复用串台。"""
    if not pane_id or not ubz_id:
        raise TmuxError("pane_id 与 ubz_id 均不能为空")
    _run(["set-option", "-p", "-t", pane_id, UBZ_PANE_OPTION, ubz_id])


def _pane_result(session: str, window: str, pane: str,
                 ubz_id: str) -> dict[str, str]:
    if ubz_id:
        tag_pane(pane, ubz_id)
    return {"session": session, "window": window, "pane": pane}


def allocate_pane(session: str, win_name: str, workdir: str,
                  max_panes: int = 0, ubz_id: str = "") -> dict[str, str]:
    """分配一个 pane 给题目, 返回定位信息。
    max_panes <= 0: 全部 pane 平铺在 session 唯一的 window 里(一屏观察);
    max_panes > 0: 每 window 这么多 pane, 满了自动开新 window。"""
    if not has_session(session):
        # 建 session 时直接用首个 window 的首个 pane 给本题, 不留闲置 shell pane
        # 显式尺寸: detached session 默认 80x24, 多分屏会太小
        pane_id = _run(["new-session", "-d", "-s", session, "-n", win_name,
                        "-c", workdir, "-x", "220", "-y", "55",
                        "-P", "-F", "#{pane_id}"]).strip()
        win_index = _run(["display-message", "-p", "-t", pane_id,
                          "#{window_index}"]).strip()
        _run(["select-pane", "-t", pane_id, "-T", win_name])
        return _pane_result(session, win_index, pane_id, ubz_id)

    if max_panes > 0:
        target = next((w for w in _windows(session) if w["panes"] < max_panes),
                      None)
    else:
        target = _windows(session)[0] if _windows(session) else None

    if target is None:
        # 开新 window, 其首个 pane 直接给本题
        pane_id = _run(["new-window", "-d", "-t", session, "-n", win_name,
                        "-c", workdir, "-P", "-F", "#{pane_id}"]).strip()
        win_index = _run(["display-message", "-p", "-t", pane_id,
                          "#{window_index}"]).strip()
    else:
        win_index = target["index"]
        pane_id = _run(["split-window", "-d", "-t", f"{session}:{win_index}",
                        "-c", workdir, "-P", "-F", "#{pane_id}"]).strip()
        _run(["select-layout", "-t", f"{session}:{win_index}", "tiled"])

    _run(["select-pane", "-t", pane_id, "-T", win_name])  # pane 标题 = 题目名
    return _pane_result(session, win_index, pane_id, ubz_id)


def pane_states() -> dict[str, PaneState]:
    """一次枚举全部 pane，包含稳定身份、前台命令和当前工作目录。"""
    out = _run(["list-panes", "-a", "-F", _PANE_LIST_FORMAT], check=False)
    states: dict[str, PaneState] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 6 or not parts[0]:
            continue
        states[parts[0]] = PaneState(*parts[1:])
    return states


def matching_pane_state(pane_id: str, session: str = "",
                        ubz_id: str = "") -> PaneState | None:
    """按 pane_id + session + attempt UUID 校验；UUID 为空仅兼容旧调用。"""
    if not pane_id:
        return None
    state = pane_states().get(pane_id)
    if state is None or (session and state.session != session):
        return None
    if ubz_id and state.ubz_id != ubz_id:
        return None
    return state


def pane_exists(pane_id: str, session: str = "", ubz_id: str = "") -> bool:
    return matching_pane_state(pane_id, session, ubz_id) is not None


def pane_current_command(pane_id: str) -> str:
    return _run(["display-message", "-p", "-t", pane_id,
                 "#{pane_current_command}"], check=False).strip()


def kill_pane(pane_id: str, session: str = "", ubz_id: str = "") -> None:
    if pane_exists(pane_id, session, ubz_id):
        _run(["kill-pane", "-t", pane_id])


def interrupt_pane(pane_id: str, times: int = 3,
                   session: str = "", ubz_id: str = "",
                   harness_name: str = "") -> None:
    """发 Ctrl+C (默认最多三次: 首击打断生成/清空输入框, 再双击退出 TUI;
    若前台已退回 shell 则提前停止)。每次都复查身份，防止间隔内 ID 被复用。
    pi 要求双击间隔 <500ms, 单独用 0.2s 且最多两击, 防止第三击落入 shell;
    其他 harness 保持实测过的 0.8s。"""
    if not pane_exists(pane_id, session, ubz_id):
        return
    interval = 0.2 if harness_name == "pi" else 0.8
    if harness_name == "pi":
        times = min(times, 2)
    for i in range(times):
        if not pane_exists(pane_id, session, ubz_id):
            return
        if i > 0:
            cur = pane_current_command(pane_id)
            if cur and cur in SHELL_CMDS:
                break
        _run(["send-keys", "-t", pane_id, "C-c"], check=False)
        time.sleep(interval)


# ---------------------------------------------------------------- 输入注入

def send_command(pane_id: str, cmd: str) -> None:
    """发送一行命令并回车 (用于启动 harness 等 ASCII 命令)。"""
    _run(["send-keys", "-t", pane_id, "-l", "--", cmd])
    _run(["send-keys", "-t", pane_id, "Enter"])


def send_text(pane_id: str, text: str, submit: bool = True) -> None:
    """经 buffer 粘贴多行文本 (bracketed paste, 不会因换行提前提交)。
    submit=True 时带提交确认: 慢启动 TUI 的首帧渲染会吞掉紧随粘贴的 Enter
    (实测 cursor 2026.09 冷启动: 粘贴完整进了输入框但 Enter 丢失,
    提示词躺在输入框里不跑), 看不到忙碌标志就补按; 已提交时输入框是空的,
    补按 Enter 无害。弹窗出现时停止补按, 弹窗归 _dismiss_dialogs 管。"""
    pre_tail = _visible_tail(pane_id, 14)
    if any(r[0] in line for r in DIALOG_RULES for line in pre_tail):
        _dismiss_dialogs(pane_id, timeout=8.0)
    buf = f"ubz-{uuid.uuid4().hex[:8]}"
    _run(["load-buffer", "-b", buf, "-"], input_text=text)
    _run(["paste-buffer", "-d", "-p", "-t", pane_id, "-b", buf])
    if not submit:
        return
    time.sleep(0.25)  # 等 TUI 消化粘贴内容再提交
    for _ in range(3):
        _run(["send-keys", "-t", pane_id, "Enter"])
        for _ in range(5):
            time.sleep(0.3)
            tail = _visible_tail(pane_id, 12)
            if is_busy(tail):
                return
            if any(r[0] in line for r in DIALOG_RULES for line in tail):
                return


def launch_harness(pane_id: str, command: str) -> None:
    """启动 harness, 后缀退出标记供 monitor 检测。"""
    send_command(pane_id, f"{command}; echo {EXIT_MARK}$?")


def wait_harness_ready(pane_id: str, timeout: float = 30.0) -> bool:
    """等 harness 就绪: 前台进程从 shell 变成 harness -> 处理信任弹窗 -> 留绘制时间。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        cmd = pane_current_command(pane_id)
        if cmd and cmd not in SHELL_CMDS:
            break
        time.sleep(0.25)
    else:
        return False
    _dismiss_dialogs(pane_id)
    time.sleep(0.4)
    return True


def _visible_tail(pane_id: str, n: int = 8) -> list[str]:
    """可见屏幕的最后 n 个非空行 (不含 scrollback, -J 合并折行)。"""
    out = _run(["capture-pane", "-p", "-J", "-t", pane_id], check=False)
    lines = [l for l in out.splitlines() if l.strip()]
    return lines[-n:]


def _dismiss_dialogs(pane_id: str, timeout: float = 15.0) -> None:
    """弹窗是底部模态: 只在屏幕尾部出现标志行时才按规则按键, 避免误触输入框。
    弹窗消失后重绘会把标志行顶出尾部, 连续两次干净即认为无弹窗。
    若屏幕最末行仍是启动命令回显 (含 echo UBZ-EXIT:), 说明 TUI 首帧尚未画出,
    此时不累加 clean, 防止多路并发慢启动时在信任窗弹出前提前退出。"""
    deadline = time.time() + timeout
    clean = 0
    while time.time() < deadline and clean < 2:
        tail = _visible_tail(pane_id, 14)
        rule = next((r for r in DIALOG_RULES
                     if any(r[0] in line for line in tail)), None)
        if rule:
            for key in rule[1]:
                _run(["send-keys", "-t", pane_id, key], check=False)
                time.sleep(0.2)
            clean = 0
            time.sleep(1.0)
        elif not tail or f"echo {EXIT_MARK}" in tail[-1]:
            clean = 0
            time.sleep(0.4)
        else:
            clean += 1
            time.sleep(0.4)


# ---------------------------------------------------------------- 输出捕获

def capture(pane_id: str, lines: int = 500) -> str:
    """抓取 pane 内容 (-J 合并折行, 避免 flag 被折行切断)。"""
    return _run(["capture-pane", "-p", "-J", "-S", f"-{lines}", "-t", pane_id])


def exit_mark_count(pane_id: str) -> int:
    """可见范围内退出标记出现次数。monitor 用计数基线区分新旧退出。"""
    try:
        return len(EXIT_RE.findall(capture(pane_id, lines=500)))
    except TmuxError:
        return 0


# ---------------------------------------------------------------- 人工接管

_TERMINAL_TEMPLATES = {
    "gnome-terminal": lambda tm: ["gnome-terminal", "--", *tm],
    "konsole":        lambda tm: ["konsole", "-e", *tm],
    "kitty":          lambda tm: ["kitty", *tm],
    "alacritty":      lambda tm: ["alacritty", "-e", *tm],
    "wezterm":        lambda tm: ["wezterm", "start", "--", *tm],
    "xterm":          lambda tm: ["xterm", "-e", *tm],
}

# 支持远程开 tab 的终端: 在现有窗口里加标签页, 没有运行实例则自动新开窗口
_TAB_TEMPLATES = {
    "gnome-terminal": lambda tm: ["gnome-terminal", "--tab", "--", *tm],
    "konsole":        lambda tm: ["konsole", "--new-tab", "-e", *tm],
    "wezterm":        lambda tm: ["wezterm", "cli", "spawn", "--", *tm],
    "kitty":          lambda tm: ["kitten", "@", "launch", "--type=tab", "--", *tm],
}


def focus_command(tmux_info: dict[str, str]) -> list[str]:
    return ["tmux", "attach", "-t", tmux_info["session"],
            ";", "select-window", "-t",
            f"{tmux_info['session']}:{tmux_info['window']}",
            ";", "select-pane", "-t", tmux_info["pane"]]


def best_client_for(session: str) -> str:
    """挑选可复用的已 attach client:
    优先 attach 在目标 session 上的; 否则取最近活跃的任何 client
    (目标 session 在后台跑着但没 attach 时, 把现有终端切过去, 不新开窗口)。"""
    out = _run(["list-clients", "-F",
                "#{client_activity}\t#{client_name}\t#{client_session}"],
               check=False)
    clients = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            act, name, sess = parts
            clients.append((int(act or 0), name, sess))
    if not clients:
        return ""
    clients.sort(reverse=True)  # 最近活跃在前
    for _act, name, sess in clients:
        if sess == session:
            return name
    return clients[0][1]


def spawn_terminal(emulator: str, tmux_info: dict[str, str]) -> str:
    """人工接管, 返回执行说明。优先级:
    1) 有可复用的已 attach client -> switch-client 把它的视图切到题目 pane
    2) 终端支持远程开 tab -> 在现有窗口里加标签页 (无实例则自动新开窗口)
    3) 兜底: 新开终端窗口"""
    state = matching_pane_state(
        tmux_info.get("pane", ""), tmux_info.get("session", ""),
        tmux_info.get("ubz_id", ""))
    if state is None:
        raise TmuxError(
            "题目 pane 不存在或身份已变化（通常是 tmux/VM 重启后旧 ID 被复用）；"
            "为防误进其他 harness，未切换终端。请点击「恢复」重新分配")
    # window_index 同样可复用，始终以当前 pane 为准，不信任 meta 里的旧值。
    tmux_info = {**tmux_info, "session": state.session, "window": state.window}
    session = state.session
    if not has_session(session):
        raise TmuxError(
            f"tmux session {session} 已不存在, 题目 pane 已被销毁; "
            f"请在面板上点「恢复」重新拉起")
    client = best_client_for(session)
    if client:
        _run(["switch-client", "-c", client, "-t",
              f"{session}:{tmux_info['window']}"])
        _run(["select-pane", "-t", tmux_info["pane"]])
        return f"已把现有终端({client})切到该题"

    tm = focus_command(tmux_info)
    build_tab = _TAB_TEMPLATES.get(emulator)
    if build_tab is not None:
        argv = build_tab(tm)
        if shutil.which(argv[0]):
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=10)
            if proc.returncode == 0:
                return "已在现有终端窗口新开标签页"
            # wezterm/kitty 无运行实例或未开远程控制时落回新开窗口

    build = _TERMINAL_TEMPLATES.get(emulator)
    if build is None:
        raise TmuxError(f"不支持的终端: {emulator} "
                        f"(支持: {', '.join(_TERMINAL_TEMPLATES)})")
    argv = build(tm)
    if shutil.which(argv[0]) is None:
        raise TmuxError(f"找不到终端程序: {argv[0]}")
    subprocess.Popen(argv, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return "已打开新终端窗口"
