"""ubz-ctf core: challenge metadata store, root-dir state, config loading.

事实源:
  - 每题目录下的 meta.json
  - ~/.ubz-ctf/state.json  保存当前根目录与最近根目录列表
  - 项目根 config.yaml     只放不变默认值(harness 命令、求助关键词等)
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
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
    "terminal_emulator": "gnome-terminal",
    "default_harness": "codex",
    "help_keywords": ["需要你", "需要人工", "人工介入", "请帮我", "帮我确认", "肉眼"],
    "download_cookies": "",
    "zip_passwords": ["infected"],
    "harnesses": {
        "codex": "codex --sandbox danger-full-access --ask-for-approval never",
        "claude": "claude --dangerously-skip-permissions",
    },
    "resume_commands": {
        "codex": "codex --sandbox danger-full-access --ask-for-approval never resume --last",
        "claude": "claude -c --dangerously-skip-permissions",
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


def set_root(path: str, create: bool = False) -> str:
    root = os.path.abspath(os.path.expanduser(path.strip()))
    if not os.path.isdir(root):
        if create:
            os.makedirs(root, exist_ok=True)
        else:
            raise ValueError(f"目录不存在: {root}")
    state = _load_state()
    state["current_root"] = root
    recent = [root] + [r for r in state.get("recent_roots", []) if r != root]
    state["recent_roots"] = recent[:20]
    _save_state(state)
    return root


def list_roots() -> dict[str, Any]:
    state = _load_state()
    return {
        "current_root": state.get("current_root"),
        "recent_roots": [
            {"path": r, "exists": os.path.isdir(r)}
            for r in state.get("recent_roots", [])
        ],
    }


def session_name_for_root(root: str) -> str:
    """tmux session 名从根目录 basename 派生: ~/ctf/2026qwb -> ctf-2026qwb"""
    base = os.path.basename(root.rstrip("/")) or "root"
    return "ctf-" + re.sub(r"[^A-Za-z0-9_-]", "-", base)


# ---------------------------------------------------------------- challenge

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
    workdir: str = ""
    root: str = ""
    tmux: dict[str, str] = field(default_factory=dict)
    status: str = "created"
    flag: str = ""
    flag_candidate: str = ""
    note: str = ""
    last_output: str = ""
    exit_seen: int = 0                   # 已确认的退出标记数基线(区分新旧退出)
    prompt_sent: bool = False            # 初始提示词是否已成功注入(决定 resume 行为)
    supplements: list[dict] = field(default_factory=list)  # 后续补充记录 [{ts, text}]
    download_status: str = ""      # "" | pending | done | partial | failed
    download_errors: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    @property
    def meta_path(self) -> Path:
        return Path(self.workdir) / "meta.json"

    def save(self) -> None:
        _atomic_write_json(self.meta_path, asdict(self))

    @classmethod
    def load(cls, meta_path: Path) -> "Challenge":
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})


def sanitize_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip()).strip("-.")
    return cleaned or "chall"


def create_challenge(root: str, *, name: str, category: str, info: str = "",
                     target: str = "", attachment_urls: Optional[list[str]] = None,
                     harness: str = "codex", custom_prompt: str = "") -> Challenge:
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
        workdir=str(workdir),
        root=root,
        tmux={"session": session_name_for_root(root)},
    )
    ch.save()
    return ch


def list_challenges(root: str) -> list[Challenge]:
    out = []
    root_path = Path(root)
    if not root_path.is_dir():
        return out
    for child in sorted(root_path.iterdir()):
        meta = child / "meta.json"
        if meta.is_file():
            try:
                out.append(Challenge.load(meta))
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
    flag 捕获功能已移除, solved 仅靠用户手动填 flag 触发。"""
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

def _atomic_write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)
