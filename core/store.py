"""ubz-ctf core: challenge metadata store, root-dir state, config loading.

事实源:
  - 每题目录下的 meta.json
  - ~/.ubz-ctf/state.json  保存当前根目录与最近根目录列表
  - 项目根 config.yaml     只放不变默认值(harness 命令、求助关键词等)
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shlex
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

PROJECT_DIR = Path(__file__).resolve().parent.parent
APP_DIR = Path.home() / ".ubz-ctf"
STATE_FILE = APP_DIR / "state.json"
CONFIG_FILE = PROJECT_DIR / "config.yaml"

DEFAULT_CONFIG: dict[str, Any] = {
    "panes_per_window": 4,
    "poll_interval": 4,
    "launch_concurrency": 2,
    "idle_poll_interval": 20,
    "capture_lines": 160,
    "resource_limits": {
        "enabled": True,
        "admission_control": True,
        "min_available_mb": 1800,
        "max_load_per_cpu": 1.5,
        "cpu_quota_per_attempt": 65,   # 旧配置兼容忽略；不再限制单路
        "scope_enabled": False,        # 只限制新启动，不限制已运行进程
    },
    "terminal_emulator": "gnome-terminal",
    "default_harness": "codex",
    "help_keywords": ["需要你", "需要人工", "人工介入", "请帮我", "帮我确认", "肉眼"],
    "download_cookies": "",
    "zip_passwords": ["infected"],
    "harnesses": {
        "codex": "codex --sandbox danger-full-access --ask-for-approval never",
        "claude": "claude --dangerously-skip-permissions",
        "cursor": "agent --force --trust",
        "dsh": "DSH_PERMISSION_MODE=danger-full-access dsh-tui",
        "kimi": "kimi --auto",
        "agy": 'GEMINI_API_KEY=magpie-agy GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:3425 agy --model "magpie/antigravity/gemini-4-argon" --dangerously-skip-permissions',
        "opencode": "opencode --auto",
        "pi": "pi --approve",
        "zcode": "zcode --mode yolo",
    },
    "resume_commands": {
        "codex": "codex --sandbox danger-full-access --ask-for-approval never resume --last",
        "claude": "claude -c --dangerously-skip-permissions",
        "cursor": "agent --continue --force --trust",
        "dsh": "DSH_PERMISSION_MODE=danger-full-access ~/unboundz-ctf/bin/dsh-resume",
        "kimi": "kimi --continue --auto",
        "agy": 'GEMINI_API_KEY=magpie-agy GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:3425 agy --continue --model "magpie/antigravity/gemini-4-argon" --dangerously-skip-permissions',
        "opencode": "opencode --continue --auto",
        "pi": "pi --continue --approve",
        "zcode": "zcode --continue --mode yolo",
    },
}

STATUSES = {
    "created", "downloading", "ready", "launching", "running",
    "need_help", "solved", "exited", "pane_gone", "stopped",
    "failed", "archived",
}


# ---------------------------------------------------------------- config

def load_config() -> dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        import yaml

        with open(CONFIG_FILE, encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
        for k, v in user_cfg.items():
            if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                cfg[k] = {**cfg[k], **v}
            else:
                cfg[k] = v
    return cfg


# ---------------------------------------------------------------- state (root dir)

def _load_state() -> dict[str, Any]:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"current_root": None, "recent_roots": []}


def _save_state(state: dict[str, Any]) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    _atomic_write_json(STATE_FILE, state)


def get_root() -> Optional[str]:
    return _load_state().get("current_root")


MODE_TRADITIONAL = "traditional"
MODE_API_AUTO = "api_auto"
COMPETITION_MODES = {MODE_TRADITIONAL, MODE_API_AUTO}


def _infer_root_mode(root: str) -> str:
    """仅用于旧数据迁移：有平台绑定的根目录保持 API 模式，其余默认传统。"""
    try:
        return (MODE_API_AUTO if any((ch.contest or {}).get("question_id")
                                    for ch in list_challenges(root))
                else MODE_TRADITIONAL)
    except OSError:
        return MODE_TRADITIONAL


def get_competition_mode(root: str | None = None) -> str:
    root = root or get_root()
    if not root:
        return MODE_TRADITIONAL
    state = _load_state()
    configured = (state.get("root_modes") or {}).get(root)
    return configured or _infer_root_mode(root)


def set_root(path: str, create: bool = False,
             competition_mode: str | None = None) -> str:
    root = os.path.abspath(os.path.expanduser(path.strip()))
    if not os.path.isdir(root):
        if create:
            os.makedirs(root, exist_ok=True)
        else:
            raise ValueError(f"目录不存在: {root}")
    if competition_mode is not None and competition_mode not in COMPETITION_MODES:
        raise ValueError(f"未知赛事模式: {competition_mode} "
                         f"(可选: {sorted(COMPETITION_MODES)})")
    state = _load_state()
    state["current_root"] = root
    recent = [root] + [r for r in state.get("recent_roots", []) if r != root]
    state["recent_roots"] = recent[:20]
    modes = state.setdefault("root_modes", {})
    if competition_mode is not None:
        modes[root] = competition_mode
    else:
        modes.setdefault(root, _infer_root_mode(root))
    _save_state(state)
    return root


def set_competition_mode(root: str, mode: str) -> str:
    if mode not in COMPETITION_MODES:
        raise ValueError(f"未知赛事模式: {mode}")
    root = os.path.abspath(os.path.expanduser(root))
    state = _load_state()
    state.setdefault("root_modes", {})[root] = mode
    _save_state(state)
    return mode


def list_roots() -> dict[str, Any]:
    state = _load_state()
    return {
        "current_root": state.get("current_root"),
        "competition_mode": get_competition_mode(),
        "recent_roots": [
            {"path": r, "exists": os.path.isdir(r),
             "competition_mode": get_competition_mode(r)}
            for r in state.get("recent_roots", [])
        ],
    }


def _legacy_session_name_for_root(root: str) -> str:
    base = os.path.basename(root.rstrip("/")) or "root"
    return "ctf-" + re.sub(r"[^A-Za-z0-9_-]", "-", base)


def session_name_for_root(root: str) -> str:
    """tmux session = 旧可读名称 + 根路径短哈希，避免同名赛事目录串在一起。"""
    normalized = os.path.abspath(os.path.expanduser(root))
    suffix = hashlib.sha256(normalized.encode()).hexdigest()[:6]
    return f"{_legacy_session_name_for_root(normalized)}-{suffix}"


# ---------------------------------------------------------------- 赛事平台 token

def get_contest_token(adapter_id: str, root: str = "") -> str:
    state = _load_state()
    if root:
        scoped = (state.get("contest_tokens_by_root") or {}).get(root) or {}
        if adapter_id in scoped:
            return scoped[adapter_id]
    # 兼容未按根目录隔离前的旧 Token；第一次保存后使用各根目录自己的值。
    return (state.get("contest_tokens") or {}).get(adapter_id, "")


def set_contest_token(adapter_id: str, token: str, root: str = "") -> None:
    """保存/清除 Token；传 root 时按赛事根目录隔离，空值也覆盖旧全局值。"""
    state = _load_state()
    if root:
        by_root = state.setdefault("contest_tokens_by_root", {})
        tokens = by_root.setdefault(root, {})
        tokens[adapter_id] = token
    else:
        tokens = state.setdefault("contest_tokens", {})
        if token:
            tokens[adapter_id] = token
        else:
            tokens.pop(adapter_id, None)
    _save_state(state)


def get_contest_host(adapter_id: str, root: str) -> str:
    state = _load_state()
    return ((state.get("contest_hosts_by_root") or {}).get(root) or {}).get(adapter_id, "")


def set_contest_host(adapter_id: str, root: str, server_host: str) -> None:
    state = _load_state()
    hosts = state.setdefault("contest_hosts_by_root", {})
    hosts.setdefault(root, {})[adapter_id] = server_host.strip().rstrip("/")
    _save_state(state)


# ---------------------------------------------------------------- challenge

# 一题多开: 每路 attempt 分到的本地端口段起点/步长 (起服务/监听只用自己的段,
# 防止多路在同一台机器上抢 1337/4444 这类惯用端口)
PORT_BASE_START = 30000
PORT_BASE_STRIDE = 1000

# 共享黑板骨架: 多路并行时事实/死路/占用声明都汇聚到这同一个文件。
# Inbox 必须留在最后: agent/人随手 `>>` 追加到文件末尾的条目会落进这个兜底区,
# 而不是污染前面的正式分区 (实测: Flags 殿后时 EOF 追加全进了 Flags)。
BOARD_MD = """# board.md — 共享黑板（多路并行协作，所有路共读共写）

## Facts（已验证的事实）

## 漏洞点（已验证可利用的漏洞：位置/类型/成因/复现，AWDP 防御路按这个接力修）

## Dead-ends（已否证的路线，别再走）

## 占用声明（对靶机有全局副作用的操作，先声明再动手，带时间戳）

## Flags（拿到的 flag 及来自哪一路）

## 补丁包（打好的修补包，来自哪一路、修了哪些点）

## Inbox（速记/来不及分类的放这里，之后任何人归档到上面分区）
"""

# 持久协作纪律: 写进 AGENTS.md (codex/cursor/dsh/kimi 每轮重读), CLAUDE.md / GEMINI.md
# 做它的符号链接给 claude / agy。提示词注入是一次性消息, context 压缩后纪律会丢, 这个文件不会。
# 注意: 不要引入 config.help_keywords 里的词。
AGENTS_MD = """# 协作纪律（ubz-ctf 共享黑板与接力规范）

本题支持多路 agent 并行或中途加开接力（各自在 runs/<harness>/ 独立目录干活）。
你们是队友，共同目标是最快拿到真实 flag。即使当前只有你一路在跑，也必须把已验证的
关键事实、漏洞点和走死的路线记上黑板，方便后续加开/恢复的路直接接棒。

## board.md 共享黑板

同目录的 board.md 是所有路共读共写的唯一证据板。**动手解题前先读一遍**，
并在以下时机写回（一行一条，追加到对应分区末尾）：

- 验证过一个事实 → `## Facts`：`- [verified] <事实>（依据：哪条命令的什么输出）`
- 验证出可利用漏洞 → `## 漏洞点`：`- [verified] <位置/类型/成因>（复现：哪条命令看到什么）`，
  一验证就写，不用等拿到 flag——（AWDP 攻防题：系统看到这条会自动开防御路接力修补）
- 走死一条路线 → `## Dead-ends`：`- <路线> — 已否证原因`。
  写死路和写事实一样有价值，能避免队友重复劳动
- 要对靶机做有全局副作用的操作（重置环境/改口令/独占账号/删关键文件）
  → 先写 `## 占用声明`：`- [HH:MM] <操作> @<你的harness>`；
  看到别人 10 分钟内的声明就绕行或换方向
- 拿到真实 flag → `## Flags`：`- <flag>（来源：<harness>，逐字见于哪条命令的输出）`
  （注意：本地自造/容器默认占位假 flag 如 `flag{test...}` / `flag{local_...}` 只记入 `## Facts`，**切勿写进 `## Flags`**）
  同一真实 flag 被多路独立拿到时，各路都应在 `## Flags` 留下自己的来源记录；
  这是独立复核，不属于重复条目，不要因为板上已有同值 flag 就省略。
- 打好修补包 → `## 补丁包`：`- <路径>（来源：<harness>，修了哪些点）`
- 来不及分类的速记 → `## Inbox`（兜底分区，之后任何人归档进上面分区）

写板方式：**优先使用原子写板命令 `ubz-board`**（自动加文件锁、按分区归位、带来源标签并去重，不会串区或冲掉队友刚写的内容）：
- `ubz-board fact "<事实>（依据：...）"`
- `ubz-board vuln "<位置/类型/成因>（复现：...）"`
- `ubz-board dead "<路线> — 已否证原因"`
- `ubz-board lock "<全局副作用操作>"`
- `ubz-board flag "<真实flag>（逐字见于...）"`
- `ubz-board patch "<修补包路径>（修了哪些点）"`

若手动编辑 `board.md`，必须把条目插到对应分区标题之下；**不要 `>>` 直接追加文件末尾**——那样只会落进最末的 Inbox 兜底区。
动笔前先搜同义条目：分区里已有同一事实/同一漏洞就改写原行、把你的依据并进去，**别平行新增第二条**——重复条目烧队友读板的 token，也埋不一致。

## 阶段性重读黑板（防闷头重复造轮子）

不要只在开局读一次空黑板！在以下两个关键节点，**必须重新执行 `cat board.md`**：
1. 完成初步静态摸底、准备动手写利用脚本（exp）或逆向解密脚本前——看队友是否已探明协议结构、关键偏移、密钥或漏洞点；
2. 某条思路连续受阻 2 次以上、准备换方向前——看队友是否已把该方向标为 Dead-end，或已给出新的突破口。

## 跨路脚本与产物只读复用（零写冲突原则）

各路的工作目录彼此独立，位于平级的 `../<harness>/`（例如 `../dsh/`、`../claude/`、`../kimi/`）。
- **写板标注完整相对路径**：在黑板上引用自己写的脚本、日志或中间产物时，请写明 `runs/<你的harness>/work/xxx.py`（或 `../<你的harness>/work/xxx.py`），不要只写 `work/xxx.py`，避免队友在自己的目录下找不到。
- **只读查看或拷贝复用，严禁跨目录直接写**：如果黑板上队友已写好协议收发脚手架、反汇编脚本或解密工具，你可以直接只读查看（`cat ../<队友harness>/...`），或先拷贝到你自己的目录下再修改运行（`cp ../<队友harness>/... ./`）；**绝对禁止直接修改、覆盖或删除其他路目录下的任何文件**，严防多路并发写冲突。

## 本地端口段

你的本地端口段由环境变量 UBZ_PORT_BASE / UBZ_PORT_END 给出：起本地服务、
监听端口、socat 一律只用这段，别用 1337/4444 这类惯用端口。

## 分工

跑得快的一路：广度优先探测，多把已否证的路线写进 Dead-ends 给队友省时间。
后加开/接棒的一路：先读板再动手，别重复已被否证的探索。

## 收工

本地打通（拿到本地 flag 并写板+写 flag.txt；防御路是补丁包写进 `## 补丁包`）
而远程靶机未开时：**停手待命，不要退出**——开了 goal 模式的把 goal 标完成，
轮询/监控循环退掉，本地起的服务实例收掉，然后停在输入框等。空闲输入框不烧
token，退出反而丢上下文、恢复有摩擦。远程一开放人会发追加消息叫醒你，拿现成
的 exp/补丁直接打远程。板上没有可接力的活时同理：别盯板子等更新，停手就是。

## 底线

flag 必须逐字来自真实执行输出，严禁臆造或提交占位符。
"""

_TOOLING_START = "<!-- UBZ-CTF-TOOLS:START -->"
_TOOLING_END = "<!-- UBZ-CTF-TOOLS:END -->"


def _with_board_tooling(text: str) -> str:
    """保留人工/项目内容，只更新受管的黑板工具定位区。"""
    base = re.sub(
        rf"\n?{re.escape(_TOOLING_START)}.*?{re.escape(_TOOLING_END)}",
        "", text, flags=re.S).rstrip()
    tool = shlex.quote(str(PROJECT_DIR / "bin" / "ubz-board"))
    block = f"""{_TOOLING_START}
## 黑板工具定位（Skills / 子进程同样适用）

启动与恢复环境提供 `UBZ_BOARD_BIN`（工具绝对路径）、`UBZ_BOARD_FILE`
（本题黑板绝对路径）和 `UBZ_WORKDIR`。Skills 派生 shell 时应保留这些变量。

**`ubz-board` 短命令找不到时，不要反复搜索或另写替代脚本，直接用：**
- 查看黑板：`{tool} show`
- 写事实：`{tool} fact "<事实>（依据：...）"`
- 写漏洞：`{tool} vuln "<位置/类型/成因>（复现：...）"`
- 写死路：`{tool} dead "<路线> — 已否证原因"`
- 多路复核：同一 flag 被多路独立拿到时，各路仍要分别写入 `## Flags`，
  不要因板上已有同值记录而省略自己的来源。

若环境变量也缺失，先回到本题工作目录，再执行上面的绝对路径命令；
不要在 Skill 安装目录或其他题目的目录里写板。
{_TOOLING_END}"""
    return base + "\n\n" + block + "\n"


BOARD_SECTION_ALIASES: dict[str, str] = {
    "fact": "## Facts",
    "facts": "## Facts",
    "事实": "## Facts",
    "vuln": "## 漏洞点",
    "vulns": "## 漏洞点",
    "漏洞": "## 漏洞点",
    "漏洞点": "## 漏洞点",
    "dead": "## Dead-ends",
    "dead-end": "## Dead-ends",
    "dead-ends": "## Dead-ends",
    "死路": "## Dead-ends",
    "lock": "## 占用声明",
    "claim": "## 占用声明",
    "占用": "## 占用声明",
    "占用声明": "## 占用声明",
    "flag": "## Flags",
    "flags": "## Flags",
    "patch": "## 补丁包",
    "pkg": "## 补丁包",
    "补丁": "## 补丁包",
    "补丁包": "## 补丁包",
    "inbox": "## Inbox",
    "速记": "## Inbox",
}


def append_board_entry(board_path: Path | str, section: str, text: str,
                       *, verified: Optional[bool] = None,
                       source: str = "") -> bool:
    """带文件锁向 board.md 指定分区原子追加一条记录 (去重、防并发覆写、防串区)。
    返回 True 表示实际新增了条目, False 表示完全重复已跳过。"""
    import fcntl

    bp = Path(board_path).resolve()
    bp.parent.mkdir(parents=True, exist_ok=True)
    lock_path = bp.parent / ".board.lock"

    sec_key = section.strip().lower().lstrip("#").strip()
    sec_prefix = BOARD_SECTION_ALIASES.get(sec_key)
    if not sec_prefix:
        for k, v in BOARD_SECTION_ALIASES.items():
            if sec_key.startswith(k):
                sec_prefix = v
                break
    if not sec_prefix:
        sec_prefix = "## Inbox"

    if verified is None:
        verified = sec_prefix in ("## Facts", "## 漏洞点")

    clean = " ".join(line.strip() for line in text.strip().splitlines() if line.strip())
    if not clean:
        return False
    if clean.startswith("- "):
        clean = clean[2:].strip()

    if sec_prefix == "## 占用声明" and not re.match(r"^\[\d{2}:\d{2}\]", clean):
        hhmm = time.strftime("%H:%M")
        clean = f"[{hhmm}] {clean}"
        if source and f"@{source}" not in clean:
            clean = f"{clean} @{source}"
    else:
        if verified and "[verified]" not in clean.lower():
            clean = f"[verified] {clean}"
        if source and f"来源：{source}" not in clean and f"来源:{source}" not in clean and f"[{source}" not in clean:
            clean = f"{clean}（来源：{source}）"

    bullet = f"- {clean}"

    with open(lock_path, "w", encoding="utf-8") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            if not bp.is_file():
                bp.write_text(BOARD_MD, encoding="utf-8")
            content = bp.read_text(encoding="utf-8")
            if "## 漏洞点" not in content:
                section_hdr = ("## 漏洞点（已验证可利用的漏洞：位置/类型/成因/复现，"
                               "AWDP 防御路按这个接力修）\n\n")
                m_dead = re.search(r"^## Dead-ends", content, re.M)
                if m_dead:
                    content = content[:m_dead.start()] + section_hdr + content[m_dead.start():]
                else:
                    content = content.rstrip() + "\n\n" + section_hdr

            pat = rf"^({re.escape(sec_prefix)}[^\n]*\n)(.*?)(?=^## |\Z)"
            m = re.search(pat, content, re.S | re.M)
            if not m:
                content = content.rstrip() + f"\n\n{sec_prefix}\n\n{bullet}\n"
                bp.write_text(content, encoding="utf-8")
                return True

            head, body = m.group(1), m.group(2)
            existing_lines = [l.strip() for l in body.splitlines() if l.strip()]
            # 归一化比对去重 (忽略尾随来源括号与首尾空白)
            norm_new = re.sub(r"（来源：[^）]+）$", "", bullet.strip())
            for ex in existing_lines:
                norm_ex = re.sub(r"（来源：[^）]+）$", "", ex)
                if sec_prefix == "## Flags" and source:
                    # 同一 flag 允许不同 harness 各自复核；同一路不重复登记。
                    ex_flag = ex[2:].split(maxsplit=1)[0] if ex.startswith("- ") else ex.split(maxsplit=1)[0]
                    new_flag = clean.split(maxsplit=1)[0]
                    source_markers = (
                        f"来源：{source}）", f"来源：{source}，",
                        f"来源:{source}）", f"来源:{source}，",
                        f"[{source} ", f"@{source} ", f"@{source}）", f"@{source}，",
                    )
                    same_source = (any(m in ex for m in source_markers)
                                   or ex.rstrip().endswith(f"@{source}"))
                    if ex_flag == new_flag and same_source:
                        return False
                    continue
                if ex == bullet or norm_ex == norm_new:
                    return False

            body_stripped = body.rstrip()
            if body_stripped:
                new_body = body_stripped + "\n" + bullet + "\n\n"
            else:
                new_body = "\n" + bullet + "\n\n"
            new_content = content[:m.start()] + head + new_body + content[m.end():]
            bp.write_text(new_content, encoding="utf-8")
            return True
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def upgrade_board_sections(ch: Challenge) -> bool:
    """老板子补新分区: 缺 ## 漏洞点 时插到 Facts 之后 (Dead-ends 之前)。
    返回是否有改动。新分区上线时给存量板子做原地升级用。"""
    board = Path(ch.workdir) / "board.md"
    if not board.is_file():
        return False
    text = board.read_text(encoding="utf-8")
    if "## 漏洞点" in text:
        return False
    section = ("## 漏洞点（已验证可利用的漏洞：位置/类型/成因/复现，"
               "AWDP 防御路按这个接力修）\n\n")
    m = re.search(r"^## Dead-ends", text, re.M)
    if m:
        text = text[:m.start()] + section + text[m.start():]
    else:   # 老板子连 Dead-ends 都没有: 追加到 Facts 之后不可考, 直接放文末前无正式分区处
        text = text.rstrip() + "\n\n" + section
    board.write_text(text, encoding="utf-8")
    return True


def ensure_collab_files(ch: Challenge) -> None:
    """落地持久纪律文件: 主目录写 AGENTS.md 真身 + CLAUDE.md / GEMINI.md 符号链接,
    再把它们链接进每路的工作目录 (旧题转换的 a0 留在主目录, 直接就能看到)。
    只要进入 attempts 模型 (哪怕当前只有 1 路) 都落地纪律文件, 确保第一路从起跑
    就把已验证事实/死路记进 board.md, 后续点 +加开 时新路能直接接棒。"""
    upgrade_board_sections(ch)
    main = Path(ch.workdir)
    agents = main / "AGENTS.md"
    current = agents.read_text(encoding="utf-8") if agents.is_file() else AGENTS_MD
    desired = _with_board_tooling(current)
    if not agents.exists() or current != desired:
        agents.write_text(desired, encoding="utf-8")
    for alias in ("CLAUDE.md", "GEMINI.md"):
        p = main / alias
        if not p.exists() and not p.is_symlink():
            os.symlink("AGENTS.md", p)
    for att in ch.attempts:
        if Path(att["workdir"]).resolve() == main.resolve():
            continue
        for name in ("AGENTS.md", "CLAUDE.md", "GEMINI.md"):
            link = Path(att["workdir"]) / name
            if not link.exists() and not link.is_symlink():
                os.symlink(os.path.join("..", "..", name), link)


@dataclass
class Challenge:
    id: str
    name: str
    category: str
    info: str = ""
    target: str = ""
    attachment_urls: list[str] = field(default_factory=list)
    harness: str = "codex"
    custom_prompt: str = ""
    awdp: bool = False                   # AWDP 攻防模式 (pwn/web 的拓展勾选): 攻击提示词加 AWDP 补充段, 可开防御路
    auto_defense: bool = True            # AWDP 漏洞点接力: 板上出现新 [verified] 漏洞点自动开/喂防御路
    defense_harness: str = ""            # 该题自动防御路用的 harness, 空=config defense_harness 兜底
    defense_rules: str = ""            # AWDP 防御规则 (修补路径/白名单命令/打包要求), 注入防御提示词的 {防御规则}
    defense_prompt: str = ""           # 该题自定义防御提示词 (创建表单预览后改过的), 空=用 prompts/defense/<category>.md
    defense_template: str = ""         # AWDP 交付压缩包模板的文件名 (attachments/ 内, 用户本地上传的平台骨架包), 注入 {防御模板}
    workdir: str = ""
    root: str = ""
    tmux: dict[str, str] = field(default_factory=dict)
    status: str = "created"
    flag: str = ""
    flag_attempt: str = ""               # flag 来自哪一路 attempt 的 id (""=未指明)
    flag_candidate: str = ""
    note: str = ""
    last_output: str = ""
    exit_seen: int = 0                   # 已确认的退出标记数基线(区分新旧退出)
    prompt_sent: bool = False            # 初始提示词是否已成功注入(决定 resume 行为)
    supplements: list[dict] = field(default_factory=list)  # 后续补充记录 [{ts, text}]
    download_status: str = ""      # "" | pending | done | partial | failed
    download_errors: list[str] = field(default_factory=list)
    contest: dict[str, Any] = field(default_factory=dict)  # 赛事平台绑定 {adapter, question_id, interactive, ...}, 空=非平台题
    attempts: list[dict] = field(default_factory=list)     # 多路并行: 见 new_attempt; 空=旧版单路题(运行字段在 ch 自身)
    board_entries: int = 0             # board.md 里的条目数 (- 开头的行, monitor 轮询更新)
    board_updated: float = 0.0         # board.md 内容最后变化的 mtime
    vuln_points: list[str] = field(default_factory=list)   # 板上 ## 漏洞点 分区的 [verified] 条目原文 (monitor 解析)
    defense_feeds: list[str] = field(default_factory=list) # 已推送/触发过防御动作的漏洞点清单 (条目数基线, 见 monitor._maybe_trigger_defense)
    defense_last_trigger: float = 0.0      # 上次防御推送/自动加开的时间戳 (冷却期防重复推)
    deliverables: list[dict] = field(default_factory=list)  # 板上解析出的可用修补包 [{path, note}], 文件真实存在才算
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        # 用于保存时的三方合并；不是 dataclass 字段，不会写进 meta。
        self._base_data = asdict(self)

    @property
    def meta_path(self) -> Path:
        return Path(self.workdir) / "meta.json"

    def save(self, *, require_existing: bool = False) -> None:
        with _path_lock(self.meta_path):
            if require_existing and not self.meta_path.is_file():
                raise FileNotFoundError(self.meta_path)
            current = asdict(self)
            latest = None
            if self.meta_path.is_file():
                try:
                    latest = json.loads(self.meta_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    latest = None
            merged = _merge_challenge_data(
                getattr(self, "_base_data", {}), current, latest)
            if latest is None or merged != latest:
                _atomic_write_json(self.meta_path, merged)
            self._adopt_saved_data(merged)
            self._base_data = copy.deepcopy(merged)

    def _adopt_saved_data(self, merged: dict) -> None:
        """把锁内合并结果同步回对象，同时尽量保留外部持有的 attempt 引用。"""
        current_units = {a.get("id"): a for a in self.attempts}
        units = []
        for data in merged.get("attempts", []):
            aid = data.get("id")
            if aid in current_units:
                unit = current_units[aid]
                unit.clear()
                unit.update(data)
                units.append(unit)
            else:
                units.append(data)
        for f in self.__dataclass_fields__:
            if f != "attempts" and f in merged:
                setattr(self, f, copy.deepcopy(merged[f]))
        self.attempts = units

    @classmethod
    def load(cls, meta_path: Path) -> "Challenge":
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


def new_attempt(aid: str, harness: str, workdir: str, session: str,
                port_base: int, directive: str = "", role: str = "attack") -> dict[str, Any]:
    """一路并行尝试。workdir 是该路的 cwd (runs/<harness>/ 或旧题转换时的主目录)。
    directive 是该路的附加指令 (如分工定位: 快的一路广度探路/后加开的先读板接力),
    启动注入时拼在提示词末尾。role: attack (默认, 攻击/解题) | defense (防御路,
    用防御提示词: 修洞保服务, 不追 flag); 旧 meta 没有 role 字段一律按 attack 看。"""
    return {
        "id": aid,
        "harness": harness,
        "role": role,
        "status": "ready",
        "workdir": workdir,
        "tmux": {"session": session, "ubz_id": uuid.uuid4().hex},
        "exit_seen": 0,
        "prompt_sent": False,
        "last_output": "",
        "note": "",
        "port_base": port_base,
        "directive": directive,
        "created_at": time.time(),
    }


def setup_attempt_dir(ch: Challenge, workdir: str) -> None:
    """建 attempt 工作目录, 并把共享的 board.md 符号链接进去。
    attempt 在自己 cwd 看到的 board.md 就是本地文件, 写的内容却汇聚到主目录同一份。
    attachments 用真目录 + sync_attempt_attachments 实体拷贝, 不用符号链接:
    IDA 这类有状态工具会在二进制旁边建 .id0/.i64 数据库, 共享同一文件会互锁互踩。
    主目录本身(旧题转换)不用链接。"""
    path = Path(workdir)
    path.mkdir(parents=True, exist_ok=True)
    if path.resolve() == Path(ch.workdir).resolve():
        return
    link = path / "board.md"
    if not link.exists():
        os.symlink(os.path.join("..", "..", "board.md"), link)
    (path / "attachments").mkdir(exist_ok=True)


def sync_attempt_attachments(ch: Challenge) -> int:
    """把主目录 attachments/ 的内容实体拷贝进每路的 attachments/ (只拷该路缺失的)。
    调用时机: 启动前(附件下载完)、上传后、加开时。返回拷贝的文件数。
    已存在的同名文件绝不覆盖——那可能是该路自己 patch 过的版本; 主目录同名更新
    要生效, 先删掉该路的那份再同步。"""
    import shutil
    src_root = Path(ch.workdir) / "attachments"
    if not src_root.is_dir():
        return 0
    copied = 0
    for att in ch.attempts:
        dst_root = Path(att["workdir"]) / "attachments"
        if dst_root.is_symlink():   # 历史布局兼容: 符号链接换真目录
            dst_root.unlink()
        dst_root.mkdir(parents=True, exist_ok=True)
        for src in src_root.rglob("*"):
            rel = src.relative_to(src_root)
            dst = dst_root / rel
            if src.is_dir():
                dst.mkdir(exist_ok=True)
                continue
            if dst.exists() or dst.is_symlink():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied += 1
    return copied


def _attempt_workdir(ch: Challenge, harness: str, taken: set[str]) -> str:
    """runs/<harness>/, harness 重复时加序号 (runs/codex-2/)。"""
    base = f"runs/{sanitize_name(harness)}"
    rel, n = base, 2
    while rel in taken or (Path(ch.workdir) / rel).exists():
        rel = f"{base}-{n}"
        n += 1
    return rel


def add_attempt(ch: Challenge, harness: str, directive: str = "",
                role: str = "attack") -> dict[str, Any]:
    """串行化 aid/workdir/port 分配，防止并发加开拿到同一路身份。"""
    ch.save()   # 先 flush 调用方修改，再在锁内刷新其它请求的新状态
    with _path_lock(ch.meta_path):
        latest = Challenge.load(ch.meta_path)
        ch._adopt_saved_data(asdict(latest))
        ch._base_data = asdict(ch)
        return _add_attempt_unlocked(ch, harness, directive, role)


def _add_attempt_unlocked(ch: Challenge, harness: str, directive: str = "",
                          role: str = "attack") -> dict[str, Any]:
    """给题目加开一路 (建目录/链接/端口段, 写 meta)。旧版单路题先转换成
    attempts 模型: 原运行字段包成 a0 (workdir 留在主目录, pane 不动)。"""
    if not ch.attempts:
        if ch.tmux.get("pane") or ch.prompt_sent:
            legacy = new_attempt("a0", ch.harness, ch.workdir,
                                 ch.tmux.get("session", ""), PORT_BASE_START)
            legacy_tmux = dict(ch.tmux)
            legacy_tmux.setdefault("ubz_id", uuid.uuid4().hex)
            legacy.update({
                "tmux": legacy_tmux, "status": ch.status,
                "exit_seen": ch.exit_seen, "prompt_sent": ch.prompt_sent,
                "last_output": ch.last_output, "note": ch.note,
            })
            ch.attempts.append(legacy)
        board = Path(ch.workdir) / "board.md"
        if not board.exists():
            board.write_text(BOARD_MD, encoding="utf-8")
    idx = 1 + max((int(a["id"][1:]) for a in ch.attempts
                   if a["id"].startswith("a") and a["id"][1:].isdigit()),
                  default=-1)   # 取现存最大编号+1: 删过中间的路也不会撞 aid/端口段
    taken = {a["workdir"] for a in ch.attempts}
    rel = _attempt_workdir(ch, harness, taken)
    workdir = str(Path(ch.workdir) / rel)
    att = new_attempt(f"a{idx}", harness, workdir,
                      ch.tmux.get("session") or session_name_for_root(ch.root),
                      PORT_BASE_START + idx * PORT_BASE_STRIDE,
                      directive=directive.strip(), role=role)
    setup_attempt_dir(ch, workdir)
    ch.attempts.append(att)
    ensure_collab_files(ch)
    ch.save()
    return att


def deliverable_name(ch: "Challenge") -> str:
    """修补包文件名: 以用户上传的交付压缩包模板的文件名称为准 (不同比赛名字不同),
    没传模板按惯例 update.tar.gz。提示词渲染和黑板解析都从这里取, 保持一致。"""
    return ch.defense_template.strip() or "update.tar.gz"


def remove_attempt(ch: Challenge, aid: str) -> dict[str, Any]:
    """从 attempts 移除一路 (pane/文件由 server 侧先处理)。返回被移除的 attempt。"""
    for a in ch.attempts:
        if a.get("id") == aid:
            ch.attempts.remove(a)
            if ch.flag_attempt == aid:
                ch.flag_attempt = ""
            ch.status = aggregate_status(ch)
            ch.save()
            return a
    raise ValueError(f"题目 {ch.name} 没有 attempt {aid}")


def unit_views(ch: Challenge) -> list[dict[str, Any]]:
    """统一运行单元: 有 attempts 返回 attempts (dict 引用, 直接改);
    旧版单路题把 ch 自身包装成一个带 _legacy 标记的单元 (改完要 apply_unit 写回)。"""
    if ch.attempts:
        return ch.attempts
    return [{
        "_legacy": True, "id": "", "harness": ch.harness,
        "workdir": ch.workdir, "tmux": ch.tmux, "status": ch.status,
        "exit_seen": ch.exit_seen, "prompt_sent": ch.prompt_sent,
        "last_output": ch.last_output, "note": ch.note, "port_base": 0,
    }]


def apply_unit(ch: Challenge, unit: dict[str, Any]) -> None:
    """旧版单元改完后写回 ch 字段; attempts 单元是引用, 调它无害。"""
    if unit.get("_legacy"):
        for k in ("status", "exit_seen", "prompt_sent", "last_output", "note"):
            setattr(ch, k, unit[k])
        if ch.flag:
            ch.status = "solved"
        ch.tmux = unit["tmux"]


# 聚合同组多路状态供卡片展示/轮询筛选: 需要人的优先, 其余按活跃度
_AGGREGATE_PRIORITY = ("need_help", "running", "launching", "downloading",
                       "ready", "created", "exited", "failed", "pane_gone",
                       "stopped", "archived")


def aggregate_status(ch: Challenge) -> str:
    if ch.flag:
        return "solved"
    if not ch.attempts:
        return ch.status
    sts = {a.get("status", "ready") for a in ch.attempts}
    for s in _AGGREGATE_PRIORITY:
        if s in sts:
            return s
    return "ready"


def find_unit(ch: Challenge, aid: str) -> dict[str, Any]:
    """按 attempt id 找运行单元; aid 空时: 单路题给唯一那路, 否则报错。"""
    units = unit_views(ch)
    if aid:
        for u in units:
            if u.get("id") == aid:
                return u
        raise ValueError(f"题目 {ch.name} 没有 attempt {aid} "
                         f"(现有: {', '.join(u.get('id', '') for u in units)})")
    if len(units) == 1:
        return units[0]
    raise ValueError(f"题目 {ch.name} 有多路 attempt, 请用 aid 指定 "
                     f"({', '.join(u['id'] for u in units)})")


def sanitize_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip()).strip("-.")
    return cleaned or "chall"


def create_challenge(root: str, *, name: str, category: str, info: str = "",
                     target: str = "", attachment_urls: Optional[list[str]] = None,
                     harness: str = "codex", custom_prompt: str = "",
                     harnesses: Optional[list[str]] = None,
                     defense_harnesses: Optional[list[str]] = None,
                     defense_rules: str = "", defense_prompt: str = "",
                     awdp: bool = False, auto_defense: bool = True,
                     defense_harness: str = "") -> Challenge:
    dirname = sanitize_name(name)
    workdir = Path(root) / dirname
    n = 2
    while (workdir / "meta.json").exists():
        workdir = Path(root) / f"{dirname}-{n}"
        n += 1
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "attachments").mkdir(exist_ok=True)

    ch = Challenge(
        id=uuid.uuid4().hex[:6],
        name=name.strip(),
        category=category,
        info=info,
        target=target,
        attachment_urls=[u for u in (attachment_urls or []) if u.strip()],
        harness=harness,
        custom_prompt=custom_prompt,
        defense_rules=defense_rules,
        defense_prompt=defense_prompt,
        awdp=awdp,
        auto_defense=auto_defense,
        defense_harness=defense_harness,
        workdir=str(workdir),
        root=root,
        tmux={"session": session_name_for_root(root)},
    )
    for h in harnesses or []:
        add_attempt(ch, h)
    # auto_defense 开时防御路不在创建期开跑: 等攻击路写下已验证漏洞点再自动接力
    # (防御从零审计 = 把攻击路的发现工作重复一遍); 关掉才维持创建即并行的旧行为
    if not auto_defense:
        for h in defense_harnesses or []:
            add_attempt(ch, h, role="defense")
    ch.save()
    return ch


_LISTING_CACHE: dict[str, tuple[tuple[int, int], dict]] = {}
_LISTING_CACHE_LIMIT = 512
_LISTING_CACHE_LOCK = threading.Lock()


def _listing_from_data(data: dict) -> "Challenge":
    known = set(Challenge.__dataclass_fields__)
    return Challenge(**{k: copy.deepcopy(v) for k, v in data.items() if k in known})


def _load_listing_challenge(meta: Path) -> "Challenge":
    """目录枚举专用缓存：返回独立对象，调用方仍可安全修改。"""
    st = meta.stat()
    key = str(meta)
    version = (st.st_mtime_ns, st.st_size)
    cached = _LISTING_CACHE.get(key)
    if cached and cached[0] == version:
        return _listing_from_data(cached[1])
    data = json.loads(meta.read_text(encoding="utf-8"))
    with _LISTING_CACHE_LOCK:
        _LISTING_CACHE[key] = (version, data)
        while len(_LISTING_CACHE) > _LISTING_CACHE_LIMIT:
            _LISTING_CACHE.pop(next(iter(_LISTING_CACHE)))
    return _listing_from_data(data)


def list_challenges(root: str) -> list[Challenge]:
    out = []
    root_path = Path(root)
    if not root_path.is_dir():
        return out
    for child in sorted(root_path.iterdir()):
        meta = child / "meta.json"
        if meta.is_file():
            try:
                out.append(_load_listing_challenge(meta))
            except (json.JSONDecodeError, OSError, TypeError):
                continue
    out.sort(key=lambda c: c.created_at)
    return out


def find_challenge(challenge_id: str, roots: Optional[list[str]] = None) -> Optional[Challenge]:
    """按 id 在当前根目录 + 最近根目录里找题目。"""
    if roots is None:
        state = list_roots()
        roots = [state["current_root"]] if state["current_root"] else []
        roots += [r["path"] for r in state["recent_roots"] if r["exists"]]
    seen = set()
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        for ch in list_challenges(root):
            if ch.id == challenge_id:
                return ch
    return None


def all_active_challenges() -> list[Challenge]:
    """跨所有最近根目录,返回需要轮询的题目。
    running/need_help/exited/solved 都在轮询集里做状态跟踪(退出/复活/pane丢失);
    flag 捕获功能已移除, solved 由用户手动保存非空 flag 触发，清空 flag 时撤销。"""
    state = list_roots()
    roots = [r["path"] for r in state["recent_roots"] if r["exists"]]
    out, seen = [], set()
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        for ch in list_challenges(root):
            if ch.status in ("running", "need_help", "exited", "solved"):
                out.append(ch)
    return out


# ---------------------------------------------------------------- util

class _PathLock:
    """线程 RLock + 进程 flock 的可重入组合，供同一 meta 的嵌套保存使用。"""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._depth = 0
        self._file = None

    @contextmanager
    def hold(self):
        with self._lock:
            if self._depth == 0:
                import fcntl
                self.path.parent.mkdir(parents=True, exist_ok=True)
                lock_path = self.path.with_name(self.path.name + ".lock")
                self._file = open(lock_path, "a", encoding="utf-8")
                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
            self._depth += 1
            try:
                yield
            finally:
                self._depth -= 1
                if self._depth == 0:
                    import fcntl
                    fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
                    self._file.close()
                    self._file = None


_PATH_LOCKS: dict[str, _PathLock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


def _path_lock(path: Path):
    key = str(path.resolve())
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = _PATH_LOCKS[key] = _PathLock(path)
    return lock.hold()


def _merge_attempts(base: list, current: list, latest: list) -> list:
    """按 aid 合并并发 attempt 更新；不同路的状态/tmux 不互相覆盖。"""
    if current == base:
        return latest
    if latest == base:
        return current
    base_by_id = {a.get("id"): a for a in base if isinstance(a, dict)}
    latest_by_id = {a.get("id"): a for a in latest if isinstance(a, dict)}
    current_by_id = {a.get("id"): a for a in current if isinstance(a, dict)}
    merged = copy.deepcopy(latest_by_id)

    # 当前对象里明确删除的路不复活；base 之后别人新增的路保留。
    for aid in base_by_id.keys() - current_by_id.keys():
        merged.pop(aid, None)

    for aid, cur in current_by_id.items():
        old = base_by_id.get(aid)
        lat = latest_by_id.get(aid)
        if old is None:
            if lat is None:
                merged[aid] = copy.deepcopy(cur)
            else:
                # 同一 aid 并发新增：保留双方字段，但显式冲突以当前操作为准。
                combined = copy.deepcopy(lat)
                combined.update(copy.deepcopy(cur))
                merged[aid] = combined
            continue
        if lat is None:
            continue   # 另一方已删除，不用旧快照复活
        if cur == old:
            merged[aid] = copy.deepcopy(lat)
            continue
        result = copy.deepcopy(lat)
        for key in set(old) | set(cur) | set(lat):
            old_value = old.get(key)
            cur_value = cur.get(key)
            if cur_value != old_value:
                result[key] = copy.deepcopy(cur_value)
            elif key not in lat and key in old:
                result.pop(key, None)
        merged[aid] = result
    return sorted(merged.values(),
                  key=lambda a: (a.get("created_at", 0), a.get("id", "")))


def _merge_challenge_data(base: dict, current: dict,
                          latest: dict | None) -> dict:
    if latest is None:
        return current
    merged = dict(latest)
    for key, cur_value in current.items():
        old_value = base.get(key)
        if cur_value == old_value:
            if key not in latest:
                merged[key] = copy.deepcopy(cur_value)
            continue
        if key == "attempts":
            merged[key] = _merge_attempts(
                old_value or [], cur_value or [], latest.get(key) or [])
        else:
            # 当前对象明确修改过的字段覆盖；未改字段保留锁内最新值。
            merged[key] = copy.deepcopy(cur_value)
    return merged


def _atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
