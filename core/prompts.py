"""ubz-ctf core: 提示词模板注册与渲染。

模板文件在 prompts/<category>.md, 纯文本可直接编辑。
变量: {题目信息} {靶机地址}/{远程地址}/{目标} {题目名称} {工作目录} {附件清单}
custom 类型不用模板, 直接用表单里的 custom_prompt (同样做变量替换)。
所有提示词末尾自动追加运行环境补充(工作目录 + flag.txt 回写要求)。
"""

from __future__ import annotations

import os
from pathlib import Path

from .store import Challenge

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "prompts"

FOOTER = (
    "\n\n———\n运行环境补充：你的工作目录是 {工作目录}。"
    "题目附件（如有）已下载并解压到其中的 attachments/ 目录，当前附件清单：\n{附件清单}\n"
    "拿到 flag 后除了直接发出来，请同时把 flag 原样写入 {工作目录}/flag.txt"
    "（文件内容只有 flag 本身，不要有多余字符）。"
)

_TARGET_ALIASES = ("靶机地址", "远程地址", "目标")


def list_templates() -> dict[str, str]:
    """{category: 模板原文}, custom 不在其中。"""
    out = {}
    if TEMPLATES_DIR.is_dir():
        for f in sorted(TEMPLATES_DIR.glob("*.md")):
            out[f.stem] = f.read_text(encoding="utf-8")
    return out


def categories() -> list[str]:
    return [*list_templates().keys(), "custom"]


def attachments_listing(workdir: str, max_lines: int = 200) -> str:
    attach_dir = Path(workdir) / "attachments"
    if not attach_dir.is_dir():
        return "（无附件）"
    lines: list[str] = []
    for dirpath, _dirnames, filenames in os.walk(attach_dir):
        for fn in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, fn), workdir)
            lines.append(rel)
            if len(lines) >= max_lines:
                lines.append("……(截断)")
                return "\n".join(lines)
    return "\n".join(lines) if lines else "（无附件）"


def render(template: str, ch: Challenge) -> str:
    target = ch.target.strip() or (
        "（暂未提供；若远程环境后续开放，会通过追加消息补充给你；"
        "若本题本身无远程环境则忽略此条）")
    text = template
    text = text.replace("{题目信息}", ch.info.strip() or "（无）")
    for alias in _TARGET_ALIASES:
        text = text.replace("{" + alias + "}", target)
    text = text.replace("{题目名称}", ch.name)
    text = text.replace("{工作目录}", ch.workdir)
    text = text.replace("{附件清单}", attachments_listing(ch.workdir))
    return text


def render_for(ch: Challenge) -> str:
    """渲染题目最终提示词 (模板 + 环境补充页脚)。"""
    if ch.category == "custom":
        body = ch.custom_prompt
    else:
        path = TEMPLATES_DIR / f"{ch.category}.md"
        if not path.is_file():
            raise ValueError(f"模板不存在: prompts/{ch.category}.md")
        body = path.read_text(encoding="utf-8")
    return render(body, ch) + render(FOOTER, ch)


def write_prompt_file(ch: Challenge) -> Path:
    """渲染并写入 <workdir>/prompt.md, 返回路径。"""
    path = Path(ch.workdir) / "prompt.md"
    path.write_text(render_for(ch), encoding="utf-8")
    return path
