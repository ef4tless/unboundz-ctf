"""ubz-ctf core: 提示词模板注册与渲染。

模板文件在 prompts/<category>.md, 纯文本可直接编辑。
变量: {题目信息} {靶机地址}/{远程地址}/{目标} {题目名称} {工作目录} {附件清单} {防御规则} {防御模板} {交付包名}
({防御规则}/{防御模板} 只在防御模板里用, 来自题目上的 defense_rules/defense_template 字段, 空则给惯例兜底;
 {交付包名} = 修补包文件名, 以交付模板文件名为准, 没传模板叫 update.tar.gz)
custom 类型不用模板, 直接用表单里的 custom_prompt (同样做变量替换)。
所有提示词末尾自动追加运行环境补充(工作目录 + flag.txt 回写要求)。

AWDP 攻防模式是 pwn/web 的拓展勾选 (Challenge.awdp): 攻击侧就是普通 CTF
(渲染不变), 勾选只解锁防御路——防御路 (attempt role=defense) 用
prompts/defense/<category>.md (子目录不当独立类型), 题目上的 defense_prompt
非空时优先于文件模板(创建表单里预览可编辑)。防御页脚的交付物是
patched/ + update.tar.gz + patch.md, 不提 flag.txt。
"""

from __future__ import annotations

from pathlib import Path

from .store import Challenge, deliverable_name

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "prompts"
DEFENSE_DIR = TEMPLATES_DIR / "defense"

FOOTER = (
    "\n\n———\n运行环境补充：你的工作目录是 {工作目录}。"
    "题目附件（如有）已下载并解压到其中的 attachments/ 目录，附件位置与查看方式：\n{附件清单}\n"
    "拿到 flag 后除了直接发出来，请同时把 flag 原样写入 {工作目录}/flag.txt"
    "（文件内容只有 flag 本身，不要有多余字符）。"
)

DEFENSE_FOOTER = (
    "\n\n———\n运行环境补充：你的工作目录是 {工作目录}。"
    "题目附件（如有）已下载并解压到其中的 attachments/ 目录，附件位置与查看方式：\n{附件清单}\n"
    "落盘：patch 后的文件放 {工作目录}/patched/ 留档，最终产物 {工作目录}/{交付包名}，"
    "修补说明写 {工作目录}/patch.md（位置、类型、改法、验证结果）。"
)

# {防御规则} 为空时的兜底: 按 AWDP 常见惯例来, 比赛方另有要求会追加消息补充
_DEFENSE_RULES_DEFAULT = (
    "（暂未提供；按常见惯例：修补路径 /home/ctf，交付产物文件名以交付模板为准"
    "（没给模板就叫 update.tar.gz），只用 cp/mv/chmod/pkill/sleep 这类常规命令；"
    "比赛方另有要求时会通过追加消息补充）")

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


def defense_categories() -> list[str]:
    """有防御模板的类型 (prompts/defense/<category>.md), 即支持 AWDP 勾选的类型;
    防御模板不当独立类型出现在类型列表里。"""
    if not DEFENSE_DIR.is_dir():
        return []
    return sorted(f.stem for f in DEFENSE_DIR.glob("*.md"))


def has_defense_template(category: str) -> bool:
    return (DEFENSE_DIR / f"{category}.md").is_file()


def attachments_listing(workdir: str, max_lines: int = 200) -> str:
    """只给解压根目录和查看命令，不把完整文件列表塞进初始提示词。

    max_lines 保留用于旧调用兼容；文件发现交给 Agent 按需执行 find。
    """
    attach_dir = Path(workdir) / "attachments"
    if not attach_dir.is_dir():
        return "（无附件）"
    return ("attachments/（已下载并解压；用 `tree -a -L 6 -I "
            "'__MACOSX|._*|__pycache__|node_modules|.git' attachments 2>/dev/null || "
            "find attachments -maxdepth 6 -type f | sort` 查看目录，优先使用 tree 的输出）")


def render(template: str, ch: Challenge) -> str:
    target = ch.target.strip() or (
        "（暂未提供；本地打通（验证 exp/拿到本地 flag）后就停手待命：不用退出、"
        "不要轮询等待，远程环境后续开放会通过追加消息叫醒你，直接打远程；"
        "若本题本身无远程环境则忽略此条）")
    text = template
    text = text.replace("{题目信息}", ch.info.strip() or "（无）")
    for alias in _TARGET_ALIASES:
        text = text.replace("{" + alias + "}", target)
    text = text.replace("{题目名称}", ch.name)
    text = text.replace("{工作目录}", ch.workdir)
    text = text.replace("{附件清单}", attachments_listing(ch.workdir))
    text = text.replace("{防御规则}",
                        ch.defense_rules.strip() or _DEFENSE_RULES_DEFAULT)
    tpl = ch.defense_template.strip()
    text = text.replace("{防御模板}", (
        f"attachments/{tpl}（平台给的交付压缩包骨架：先解开参照其目录结构，"
        "交付产物按它打）" if tpl else
        "（无；按防御规则给出的结构，没给就按原服务的目录结构打包）"))
    text = text.replace("{交付包名}", deliverable_name(ch))
    return text


def render_for(ch: Challenge) -> str:
    """渲染题目最终提示词 (模板 + 环境补充页脚)。
    AWDP 的攻击侧就是普通 CTF, 渲染不变; awdp 标记只解锁防御路。"""
    if ch.category == "custom":
        body = ch.custom_prompt
    else:
        path = TEMPLATES_DIR / f"{ch.category}.md"
        if not path.is_file():
            raise ValueError(f"模板不存在: prompts/{ch.category}.md")
        body = path.read_text(encoding="utf-8")
    return render(body, ch) + render(FOOTER, ch)


def render_defense_for(ch: Challenge) -> str:
    """防御路的提示词: 题目自带的 defense_prompt 优先, 否则 prompts/defense/<category>.md;
    页脚是防御版 (交付补丁 + update.tar.gz, 不写 flag.txt)。"""
    if ch.defense_prompt.strip():
        body = ch.defense_prompt
    else:
        path = DEFENSE_DIR / f"{ch.category}.md"
        if not path.is_file():
            raise ValueError(f"防御模板不存在: prompts/defense/{ch.category}.md")
        body = path.read_text(encoding="utf-8")
    return render(body, ch) + render(DEFENSE_FOOTER, ch)


def attempt_suffix(port_base: int, board_entries: int = 0) -> str:
    """多路并行时追加在提示词末尾的指针 (server 侧拼接, 不动模板)。
    纪律全文在 AGENTS.md (harness 每轮重读, context 压缩不丢), 这里只留
    一句指针 + 该路专属的端口段数字, 避免两处重复堆长文。
    黑板已有内容时再点一句"先读板接力" (空板不提, 不烧 token)。
    注意: 不要引入 config.help_keywords 里的词, 否则回显会误触 need_help。"""
    text = (
        "\n\n———\n协作纪律（系统注入）：本题多路并行解题，共享黑板 board.md 的"
        "读写规矩见工作目录的 AGENTS.md，按它执行（推荐用 `ubz-board fact/vuln/dead/flag \"...\"` 原子写板）。"
        f"你这一路分到的本地端口段是 {port_base}-{port_base + 999}"
        "（环境变量 UBZ_PORT_BASE / UBZ_PORT_END），监听端口、起本地服务只用这段。"
    )
    if board_entries > 0:
        text += (f"\n共享黑板上已有 {board_entries} 条队友成果"
                 "（事实/已否证的路线/占用声明），动手前先读一遍 board.md 再规划。")
    return text


def solo_suffix(port_base: int, board_entries: int = 0) -> str:
    """普通单路起跑时的黑板与端口指针: 随时可能点 +加开 派队友接力,
    从第一路起就把已验证事实与死路记进 board.md, 消除加开时的黑板断层。"""
    text = (
        "\n\n———\n接力记录（系统注入）：工作目录的 board.md 是本题共享证据黑板"
        "（详细规矩见 AGENTS.md，可用 `ubz-board fact/vuln/dead/flag \"...\"` 原子写板），"
        "请在验证关键事实、漏洞点或排除死路时顺手写板，供后续加开或恢复的路直接接力。"
        f"你这一路分到的本地端口段是 {port_base}-{port_base + 999}"
        "（环境变量 UBZ_PORT_BASE / UBZ_PORT_END），监听端口、起本地服务只用这段。"
    )
    if board_entries > 0:
        text += (f"\n共享黑板上已有 {board_entries} 条已有成果"
                 "，动手前先读一遍 board.md 再规划。")
    return text


def awdp_solo_suffix(port_base: int) -> str:
    """AWDP 单攻击路的协作指针 (attempt_suffix 的单路版): 防御路还没开,
    但黑板/纪律文件已落地 (store.ensure_collab_files 对 AWDP 单路也生效),
    端口段照发。不引入 config.help_keywords 里的词。"""
    return (
        "\n\n———\n协作纪律（系统注入）：本题 AWDP 攻防对抗，防御路会在你写下"
        "已验证漏洞点后自动加入并肩作战。共享黑板 board.md 的读写规矩见工作目录的"
        " AGENTS.md，按它执行（可用 `ubz-board vuln/fact/dead \"...\"` 原子写板）。"
        f"你这一路分到的本地端口段是 {port_base}-{port_base + 999}"
        "（环境变量 UBZ_PORT_BASE / UBZ_PORT_END），监听端口、起本地服务只用这段。"
    )


# AWDP 接力 (攻击路专属, 拼在提示词最末): 漏洞点一验证就写板,
# monitor 看到 ## 漏洞点 区的新 [verified] 条目会自动开防御路/推给在跑的防御路。
# 不引入 config.help_keywords 里的词。
AWDP_RELAY_SUFFIX = (
    "\n\n———\nAWDP 接力（系统注入）：漏洞点一经验证（能控制崩溃/绕过校验，"
    "有复现依据）就立刻写进 board.md 的 ## 漏洞点 分区："
    "`- [verified] <位置/类型/成因>（复现依据）`，不用等 exp 写完——"
    "系统看到会自动开防御路按这条接力修补，你继续写完整 exp 拿 flag。"
)


def write_prompt_file(ch: Challenge) -> Path:
    """渲染并写入 <workdir>/prompt.md, 返回路径。"""
    path = Path(ch.workdir) / "prompt.md"
    path.write_text(render_for(ch), encoding="utf-8")
    return path
