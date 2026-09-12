"""ubz-ctf core: harness 适配层。

harness 只是"一条启动命令", 在 config.yaml 的 harnesses 表里配置,
名字随意 (codex/claude/自定义都行), Web 表单的 harness 下拉框动态取自该表。
resume_commands 表同理, 用于 pane 里进程退出后的恢复。

resume 恢复实测行为 (codex 0.153 / claude 2.1 / cursor 2026.09 / dsh-tui 0.10):
- codex resume --last: 默认按 cwd 过滤选最近会话; 有未完成 goal 时弹
  "Resume paused goal?" (默认项即 Resume goal, 由 tmuxctl.DIALOG_RULES 处理),
  确认后 goal active 自动继续干活; 无 goal 的会话恢复后停在输入框, 需要推一下
- claude -c: 恢复当前目录最近会话, 停在输入框, 需要推一下
- agent --continue: 恢复当前目录最近会话 (等效于退出时提示的 agent --resume=<id>),
  停在输入框, 需要推一下; --trust 跳过新目录信任弹窗, --force 免逐条批准命令
- dsh-tui --resume <id>: 由 bin/dsh-resume 按 cwd 解析出本目录最近会话再恢复
  (裸 --resume 读全局 ~/.dsh-tui/resume.txt 会串题), 停在输入框, 需要推一下;
  DSH_PERMISSION_MODE=danger-full-access = 沙箱全开+审批全免, 无信任弹窗
"""

from __future__ import annotations

import time

from . import tmuxctl

RESUME_NUDGE = ("继续你刚才的解题任务，保持原定目标不变，直到拿到真实 flag；"
                "拿到后第一时间原样发出来，并写入 flag.txt。")

# 空闲输入框的行首标志 (codex › / claude ❯ / cursor → / dsh-tui ❯)
IDLE_PROMPT_PREFIXES = ("›", "❯", "→")

# 慢启动 harness: 名字 -> 等输入框出现的额外秒数。
# dsh-tui 冷启动要拉起一串 MCP server (idalib/jadx/r2/tmux), 实测 30-60s;
# 前台进程早就不是 shell 但 UI 没挂完, 这时注入的提示词会直接丢失 (实测),
# 所以必须等到看见输入框 (❯ 行) 才算就绪。
BOOT_PROMPT_WAIT = {"dsh": 75.0}


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
    """等 harness 真的可以喂提示词: 进程就绪后, 慢启动 TUI 再等输入框出现。
    超时也放行 (注入丢失只影响该题, 用户可手动补发), 返回是否等到输入框。"""
    if not tmuxctl.wait_harness_ready(pane_id, timeout=timeout):
        return False
    extra = BOOT_PROMPT_WAIT.get(harness_name, 0)
    if extra <= 0:
        return True
    deadline = time.time() + extra
    while time.time() < deadline:
        tail = tmuxctl._visible_tail(pane_id, 6)
        if any(l.lstrip().startswith(IDLE_PROMPT_PREFIXES) for l in tail):
            time.sleep(1.0)  # 输入框刚挂出来, 留一拍再粘贴
            return True
        time.sleep(1.0)
    return False


def nudge_to_continue(pane_id: str, harness_name: str, timeout: float = 20.0) -> None:
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
        tail_lines = tmuxctl._visible_tail(pane_id, 10)
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
        if ("Pursuing goal" in tail or "Working (" in tail
                or "ctrl+c to stop" in tail
                or "esc to interrupt" in tail or "esc 中断" in tail):
            return
        if any(l.lstrip().startswith(IDLE_PROMPT_PREFIXES) for l in tail_lines):
            idle_streak += 1
            if idle_streak >= 4:
                break
        else:
            idle_streak = 0
        time.sleep(1)
    tmuxctl.send_text(pane_id, RESUME_NUDGE)
