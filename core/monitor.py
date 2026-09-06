"""ubz-ctf core: 后台监控循环。

每 poll_interval 秒对所有活跃题目(跨所有最近根目录)做:
  1. capture-pane 抓取 —— 求助关键词 / UBZ-EXIT 退出标记 / 最近输出快照
  2. pane 存活检查     —— pane 消失标记 pane_gone; exited 题目检测到非 shell
                         前台进程(用户手动拉起 harness)自动回 running
flag 捕获功能已移除: solved 状态由用户手动填 flag 触发。
另维护 elsewhere_running (非当前根目录里仍在跑的题目数) 供前端提示。
"""

from __future__ import annotations

import asyncio
import re

from . import store, tmuxctl

# codex/claude TUI 里 agent 输出的行首标志; 用于把"提示词回显"排除出求助关键词扫描
# (misc 模板自身就含"需要人工"等词, 回显会被误判成求助)
# codex 用 •, claude 新版用 ●, 旧版 ⏺
AGENT_LINE_PREFIXES = ("•", "●", "⏺")


class Monitor:
    def __init__(self, config: dict):
        self.config = config
        self.interval = float(config.get("poll_interval", 4))
        self.help_keywords = config.get("help_keywords", [])
        self.elsewhere_running = 0
        self._task: asyncio.Task | None = None

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def _loop(self) -> None:
        while True:
            try:
                await self.poll_once()
            except Exception:  # 监控循环永不退出
                pass
            await asyncio.sleep(self.interval)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------ one round

    async def poll_once(self) -> None:
        challenges = await asyncio.to_thread(store.all_active_challenges)
        current_root = store.get_root()
        self.elsewhere_running = sum(
            1 for c in challenges
            if c.root != current_root and c.status in ("running", "need_help"))
        for ch in challenges:
            try:
                await asyncio.to_thread(self._poll_challenge, ch)
            except Exception:
                continue

    # ------------------------------------------------------------ per challenge

    def _poll_challenge(self, ch: store.Challenge) -> None:
        dirty = False

        pane = ch.tmux.get("pane", "")
        if not pane or not tmuxctl.pane_exists(pane):
            if ch.status != "pane_gone":
                ch.status = "pane_gone"
                dirty = True
        else:
            try:
                text = tmuxctl.capture(pane, lines=500)
            except tmuxctl.TmuxError:
                text = ""
            if text:
                # 退出判定双保险:
                #  1) 计数基线: 新出现的独占行 UBZ-EXIT:N (scrollback 旧标记不重复触发)
                #  2) 进程探针: running 但 pane 前台已退回 shell (覆盖手动启动无标记命令的情况)
                count = len(tmuxctl.EXIT_RE.findall(text))
                if count < ch.exit_seen:
                    ch.exit_seen = count   # 旧标记滚出捕获窗口, 校准基线
                    dirty = True

                if ch.status in ("running", "need_help", "solved"):
                    cur = tmuxctl.pane_current_command(pane)
                    harness_gone = (not cur) or (cur in tmuxctl.SHELL_CMDS)
                    if count > ch.exit_seen or harness_gone:
                        ch.exit_seen = max(count, ch.exit_seen)
                        ch.status = "exited"
                        dirty = True
                    elif (ch.status == "running"
                          and self._agent_asking_help(text)):
                        ch.status = "need_help"
                        dirty = True
                elif ch.status == "exited":
                    if count > ch.exit_seen:
                        # 恢复后又真退出了一次, 记录但保持 exited
                        ch.exit_seen = count
                        dirty = True
                    else:
                        # 用户在 pane 里手动拉起了 harness -> 自动回到 running
                        cur = tmuxctl.pane_current_command(pane)
                        if cur and cur not in tmuxctl.SHELL_CMDS:
                            ch.status = "running"
                            dirty = True

                tail = self._tail(text)
                if tail != ch.last_output:
                    ch.last_output = tail
                    dirty = True

        if dirty:
            ch.save()

    def _agent_asking_help(self, text: str) -> bool:
        """只看最近输出里的 agent 行(TUI 行首 •/⏺); 找不到这类行(非 TUI harness)才看全部。"""
        lines = [l for l in text.rstrip().splitlines() if l.strip()]
        tail = lines[-20:]
        agent = [l for l in tail if l.lstrip().startswith(AGENT_LINE_PREFIXES)]
        haystack = "\n".join(agent or tail)
        return any(k in haystack for k in self.help_keywords)

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _tail(text: str, n: int = 20) -> str:
        """末尾 n 行原样返回 (TUI 底栏也在其中, 行数给足即可看到真实内容)。"""
        lines = [l.rstrip() for l in text.rstrip().splitlines()]
        lines = [l for l in lines if l]
        return "\n".join(lines[-n:])
