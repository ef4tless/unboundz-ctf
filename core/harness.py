"""ubz-ctf core: harness 适配层。

harness 只是"一条启动命令", 在 config.yaml 的 harnesses 表里配置,
名字随意 (codex/claude/自定义都行), Web 表单的 harness 下拉框动态取自该表。
resume_commands 表同理, 用于 pane 里进程退出后的恢复。

resume 恢复实测行为 (codex 0.153 / claude 2.1):
- codex resume --last: 默认按 cwd 过滤选最近会话; 有未完成 goal 时弹
  "Resume paused goal?" (默认项即 Resume goal, 由 tmuxctl.DIALOG_RULES 处理),
  确认后 goal active 自动继续干活; 无 goal 的会话恢复后停在输入框, 需要推一下
- claude -c: 恢复当前目录最近会话, 停在输入框, 需要推一下
"""

from __future__ import annotations

import time

from . import tmuxctl

RESUME_NUDGE = ("继续你刚才的解题任务，保持原定目标不变，直到拿到真实 flag；"
                "拿到后第一时间原样发出来，并写入 flag.txt。")


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


def nudge_to_continue(pane_id: str, harness_name: str, timeout: float = 20.0) -> None:
    """resume 后让 agent 真正继续干活的小状态机:
    - 出现 "Resume paused goal?" -> 回车选默认的 Resume goal (有 goal 才弹, 无 goal 不弹不按)
    - 状态栏出现 Pursuing goal / Working -> goal 已激活在自动追, 不打扰
    - 空闲输入框(›/❯)稳定 4s 才判定无弹窗 -> 发续跑指令
      (goal 弹窗在历史回放后才出现, 实测约 5-6s, 不能看到输入框就立刻发)
    """
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
        if "Pursuing goal" in tail or "Working (" in tail:
            return
        if any(l.lstrip().startswith(("›", "❯")) for l in tail_lines):
            idle_streak += 1
            if idle_streak >= 4:
                break
        else:
            idle_streak = 0
        time.sleep(1)
    tmuxctl.send_text(pane_id, RESUME_NUDGE)
