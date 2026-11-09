"""ubz-ctf core: harness 适配层。

harness 只是"一条启动命令", 在 config.yaml 的 harnesses 表里配置,
名字随意 (codex/claude/自定义都行), Web 表单的 harness 下拉框动态取自该表。
resume_commands 表同理, 用于 pane 里进程退出后的恢复。

resume 恢复实测行为 (codex 0.153 / claude 2.1 / cursor 2026.09 / dsh-tui 0.10 /
pi 1.5 / zcode 0.17):
- codex resume --last: 默认按 cwd 过滤选最近会话; 有未完成 goal 时弹
  "Resume paused goal?" (默认项即 Resume goal, 由 tmuxctl.DIALOG_RULES 处理),
  确认后 goal active 自动继续干活; 无 goal 的会话恢复后停在输入框, 需要推一下
- claude -c: 恢复当前目录最近会话, 停在输入框, 需要推一下
- agent --continue: 恢复当前目录最近会话 (等效于退出时提示的 agent --resume=<id>),
  停在输入框, 需要推一下; --trust 跳过新目录信任弹窗, --force 免逐条批准命令
- dsh-tui --resume <id>: 由 bin/dsh-resume 按 cwd 解析出本目录最近会话再恢复
  (裸 --resume 读全局 ~/.dsh-tui/resume.txt 会串题), 停在输入框, 需要推一下;
  DSH_PERMISSION_MODE=danger-full-access = 沙箱全开+审批全免, 无信任弹窗
- pi --continue --approve: 恢复当前目录最近会话并信任项目资源;
  空闲输入框没有行首提示符, 用底部 context 统计行识别
- zcode --continue --mode yolo: 恢复当前目录最近会话并跳过普通工具审批;
  空闲输入框用 Type a prompt / 输入提示词 占位文案识别
"""

from __future__ import annotations

import re
import time

from . import tmuxctl

RESUME_NUDGE = ("继续你刚才的解题任务，保持原定目标不变，直到拿到真实 flag；"
                "拿到后第一时间原样发出来，并写入 flag.txt。")

# 防御路的续跑指令: 不提 flag, 防止把修洞的 agent 拽去找 flag
DEFENSE_RESUME_NUDGE = ("继续你刚才的防御任务，保持原定目标不变：没修完的漏洞继续修，"
                        "修完按最初要求把 patched/ 补丁和 patch.md 落盘，"
                        "并确认服务功能正常、原漏洞已失效。")

# 空闲输入框的行首标志:
# codex › / claude ❯ / cursor → / dsh-tui 0.16+ ⌸ ❯ (旧版 ❯) / kimi │ > / agy > / opencode ┃
# zcode 用输入框占位文案 (busy 时会变成 Type to queue input / 输入内容会排队)
IDLE_PROMPT_PREFIXES = ("›", "❯", "→", "⌸ ❯", "│ >", ">", "┃",
                        "│ Type a prompt", "│ 输入提示词")

# pi 的编辑器为空时没有任何行首提示符; 底部 context 统计行却始终存在。
# 只检查可见尾部最后两行, 且调用方会排除忙碌态, 避免把历史输出当输入框。
_PI_IDLE_FOOTER_RE = re.compile(
    r"(?:^|\s)(?:\?|\d+(?:\.\d+)?)%/\S+(?:\s+\(auto\))?(?:\s|$)"
)

# 信任弹窗的选项行同样可能以 ❯ 或 > 开头, 绝不可误判为空闲输入框
_DIALOG_OPTION_TEXTS = (
    "Yes, I trust this folder",
    "Trust and continue",
    "No, exit",
)

# 虽已画出输入框但后端尚未就绪的底栏标志:
# dsh-tui 0.16 先画 ⌸ ❯ 再加载上下文/MCP; zcode 先画输入框再加载模型/MCP
_BOOTING_MARKERS = ("正在启动 DSH", "Starting DSH", "│ - - | -")

# 各 harness 启动后等空闲输入框出现的上限秒数。
# dsh-tui 冷启动要拉起一串 MCP server (idalib/jadx/r2/tmux), 实测 10-60s;
# claude / cursor / kimi / agy / codex / opencode 在多路并发拉起时(经历 zshrc/nvm 初始化 +
# 目录信任弹窗)也需要数秒才能画出空闲输入框, 必须等看到真实输入框再粘贴提示词
# (避免把回车打在 claude 默认选中 "No, exit" 的信任弹窗上导致直接退出)。
BOOT_PROMPT_WAIT = {
    "dsh": 75.0,
    "claude": 25.0,
    "codex": 20.0,
    "cursor": 20.0,
    "kimi": 20.0,
    "agy": 20.0,
    "opencode": 20.0,
    "pi": 20.0,
    "zcode": 30.0,
}


def _has_idle_prompt(tail_lines: list[str]) -> bool:
    """判断可见尾部行是否出现就绪的空闲输入框 (排除信任弹窗与启动未就绪态)。"""
    if any(r[0] in line for r in tmuxctl.DIALOG_RULES for line in tail_lines):
        return False
    if any(m in line for m in _BOOTING_MARKERS for line in tail_lines):
        return False
    for line in tail_lines:
        s = line.lstrip()
        if s.startswith(IDLE_PROMPT_PREFIXES):
            if any(opt in s for opt in _DIALOG_OPTION_TEXTS):
                continue
            return True
    # pi 忙碌时底部统计行仍在, 但编辑器上边框会画 spinner + Working;
    # 必须先过统一 busy 判定, 否则会把 Working 中的会话误判成空闲。
    if not tmuxctl.is_busy(tail_lines):
        return any(_PI_IDLE_FOOTER_RE.search(line) for line in tail_lines[-2:])
    return False


def harness_names(config: dict) -> list[str]:
    return list(config.get("harnesses", {}).keys())


def launch_command(config: dict, harness: str) -> str:
    cmd = config.get("harnesses", {}).get(harness)
    if not cmd:
        raise ValueError(f"未配置的 harness: {harness} "
                         f"(已配置: {', '.join(harness_names(config))})")
    return cmd


def resume_command(config: dict, harness: str) -> str:
    return (config.get("resume_commands", {}).get(harness)
            or launch_command(config, harness))


def wait_ready(pane_id: str, harness_name: str, timeout: float = 30.0) -> bool:
    """等 harness 真的可以喂提示词: 进程就绪后, 再等空闲输入框出现(期间持续处理信任弹窗)。
    超时也放行 (注入丢失只影响该题, 用户可手动补发), 返回是否等到输入框。"""
    if not tmuxctl.wait_harness_ready(pane_id, timeout=timeout):
        return False
    extra = BOOT_PROMPT_WAIT.get(harness_name, 15.0)
    if extra <= 0:
        return True
    deadline = time.time() + extra
    while time.time() < deadline:
        tail = tmuxctl._visible_tail(pane_id, 12)
        rule = next((r for r in tmuxctl.DIALOG_RULES
                     if any(r[0] in line for line in tail)), None)
        if rule:
            for key in rule[1]:
                tmuxctl._run(["send-keys", "-t", pane_id, key], check=False)
                time.sleep(0.2)
            time.sleep(1.0)
            continue
        if _has_idle_prompt(tail):
            time.sleep(0.4)  # 输入框刚挂出来, 留 0.4s 稳定期即刻粘贴
            return True
        time.sleep(0.4)
    return False


def nudge_to_continue(pane_id: str, harness_name: str, timeout: float = 20.0,
                      nudge_text: str = RESUME_NUDGE) -> None:
    """resume 后让 agent 真正继续干活的小状态机:
    - 出现 "Resume paused goal?" -> 回车选默认的 Resume goal (有 goal 才弹, 无 goal 不弹不按)
    - 状态栏出现 Pursuing goal / Working ( -> goal 已激活在自动追, 不打扰
    - 输入行右侧出现 ctrl+c to stop -> cursor 正在跑, 不打扰
      (cursor 忙时输入框同样有 → 提示符, 必须先判忙再判闲)
    - 底栏出现 esc to interrupt / esc 中断 -> dsh-tui 正在跑, 不打扰
      (⚓ Thinking 行完工后会留在 scrollback 里, 不能当忙碌标志)
    - 空闲输入框(›/❯/→)稳定 4s 才判定无弹窗 -> 发续跑指令
      (goal 弹窗在历史回放后才出现, 实测约 5-6s, 不能看到输入框就立刻发)
    """
    # 慢启动 harness (dsh-tui) 恢复时同样要拉起 MCP, 20s 内输入框都不会出现,
    # 超时即发会把续跑指令丢进还在启动的 TUI 里, 所以把 deadline 拉长
    timeout = max(timeout, BOOT_PROMPT_WAIT.get(harness_name, 0) + 20)
    deadline = time.time() + timeout
    idle_streak = 0
    while time.time() < deadline:
        tail_lines = tmuxctl._visible_tail(pane_id, 12)
        tail = "\n".join(tail_lines)
        if "Resume paused goal?" in tail:
            tmuxctl._run(["send-keys", "-t", pane_id, "Enter"], check=False)
            time.sleep(2)
            idle_streak = 0
            continue
        if "Press enter to confirm" in tail:
            time.sleep(1)  # 弹窗在但标志行被顶出尾部, 等下一轮
            idle_streak = 0
            continue
        if tmuxctl.is_busy(tail_lines):
            return
        if _has_idle_prompt(tail_lines):
            idle_streak += 1
            if idle_streak >= 4:
                break
        else:
            idle_streak = 0
        time.sleep(1)
    tmuxctl.send_text(pane_id, nudge_text)
