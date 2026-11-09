"""ubz-ctf core: 后台监控循环。

每 poll_interval 秒对所有活跃题目(跨所有最近根目录)做:
  1. capture-pane 抓取 —— 求助关键词 / UBZ-EXIT 退出标记 / 忙碌与空闲状态
     (终端正文不再写入 meta；会话查看与操作统一在 tmux 中完成)
  2. pane 存活检查     —— pane 消失标记 pane_gone; exited 题目检测到非 shell
                         前台进程(用户手动拉起 harness)自动回 running
  3. board.md 轮询     —— 条目数/修补包解析; AWDP+auto_defense 题发现
                         ## 漏洞点 区新 [verified] 条目时进触发队列,
                         由 server 注册的 defense_handler 自动开/喂防御路
flag 捕获功能已移除: solved 状态由用户手动保存非空 flag 触发，清空 flag 时撤销。
另维护 elsewhere_running (非当前根目录里仍在跑的题目数) 供前端提示。
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from pathlib import Path

from . import harness, jevgate, store, tmuxctl

# codex/claude TUI 里 agent 输出的行首标志; 用于把"提示词回显"排除出求助关键词扫描
# (misc 模板自身就含"需要人工"等词, 回显会被误判成求助)
# codex 用 •, claude 新版用 ●, 旧版 ⏺
AGENT_LINE_PREFIXES = ("•", "●", "⏺")
logger = logging.getLogger("ubz.monitor")


class Monitor:
    def __init__(self, config: dict):
        self.config = config
        self.interval = float(config.get("poll_interval", 4))
        self.help_keywords = config.get("help_keywords", [])
        self.elsewhere_running = 0
        # 只读终端预览：仅内存保存，输出变化使用独立 revision，不写 meta。
        self.outputs: dict[str, dict[str, str]] = {}
        self.output_revision = 0
        self._round_outputs: dict[str, dict[str, str]] = {}
        self._prompt_cache: dict[str, str] = {}  # workdir -> 注入的 prompt.md 原文
        self._task: asyncio.Task | None = None
        # AWDP 漏洞点接力: (challenge_id, 当前漏洞点全量清单, 触发前的消费基线)
        # 待触发队列。_poll_board 在 to_thread 里发现条目数增长就入队, poll_once
        # 回到事件循环后 drain 给 defense_handler (server 注册: 先过 Jev 语义闸门,
        # 再自动开防御路/推消息给在跑防御路)。
        self._defense_requests: list[tuple[str, list[str], list[str]]] = []
        self.defense_handler = None
        # Jev 求助二审缓存: pane/workdir -> (屏幕内容哈希, 判定); 屏幕不变不重复调 API
        self._help_verdicts: dict[str, tuple[int, bool]] = {}
        # 空转判定的 Jev 限流: pane/workdir -> 上次判定时间戳
        self._spin_checked: dict[str, float] = {}
        self._next_poll: dict[str, float] = {}
        self.last_poll_at = 0.0
        self.last_poll_duration = 0.0
        self.error_count = 0
        self.last_error = ""
        self.last_error_at = 0.0
        self._last_error_log = 0.0

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    def seed_deliverables(self) -> None:
        """升级播种: deliverables 是后加字段, 老板子的 board_updated 已是当前
        mtime, _poll_board 不会重读。启动时强制解析一次, 让已经写在板上的
        修补包立即上面板。覆盖面 = 活跃轮询集 + 当前根目录全部题目
        (pane_gone 的题板子不会再变, 播种这一次就够; 后续变化靠轮询集)。"""
        chs = {c.id: c for c in store.all_active_challenges()}
        root = store.get_root()
        if root:
            for c in store.list_challenges(root):
                chs.setdefault(c.id, c)
        for ch in chs.values():
            board = Path(ch.workdir) / "board.md"
            if not board.is_file():
                continue
            store.upgrade_board_sections(ch)   # 老板子补 ## 漏洞点 分区
            try:
                content = board.read_text(encoding="utf-8")
                ds = self._parse_deliverables(ch, content)
                vulns = self._parse_vuln_points(content)
            except OSError:
                continue
            dirty = False
            if ds != ch.deliverables:
                ch.deliverables = ds
                dirty = True
            # 漏洞点一并播种: 板上已有的条目记为已消费, 重启不补触发
            # (要开防御路人工点加开; 否则每次重启都把旧漏洞点重新接力一遍)
            if vulns != ch.vuln_points:
                ch.vuln_points = vulns
                dirty = True
            if ch.defense_feeds != vulns:
                ch.defense_feeds = list(vulns)
                dirty = True
            if dirty:
                ch.save()

    def _record_error(self, label: str, exc: Exception) -> None:
        self.error_count += 1
        self.last_error = f"{label}: {type(exc).__name__}: {exc}"
        self.last_error_at = time.time()
        now = time.time()
        if now - self._last_error_log >= 60:
            self._last_error_log = now
            logger.exception("监控错误（60s 内后续错误仅计数）: %s", label)

    async def _loop(self) -> None:
        while True:
            started = time.monotonic()
            try:
                await self.poll_once()
                self.last_poll_duration = time.monotonic() - started
                self.last_poll_at = time.time()
            except Exception as exc:  # 监控循环永不退出，但错误必须可观测
                self._record_error("poll_once", exc)
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
        self._round_outputs = {}
        challenges = await asyncio.to_thread(store.all_active_challenges)
        # 全轮共享一次 pane 枚举，替代每路 pane_exists + pane_current_command。
        pane_states = (await asyncio.to_thread(tmuxctl.pane_states)
                       if challenges else {})
        current_root = store.get_root()
        self.elsewhere_running = sum(
            1 for c in challenges
            if c.root != current_root and c.status in ("running", "need_help"))
        now = time.monotonic()
        active_ids = {c.id for c in challenges}
        self._next_poll = {cid: ts for cid, ts in self._next_poll.items()
                           if cid in active_ids}
        for ch in challenges:
            try:
                units = getattr(ch, "attempts", []) or []
                busy = (ch.status in ("running", "need_help", "launching")
                        or any(u.get("status") in ("running", "need_help", "launching")
                               for u in units))
                if not busy and now < self._next_poll.get(ch.id, 0):
                    continue
                delay = (self.interval if busy else
                         float(self.config.get("idle_poll_interval", 20)))
                self._next_poll[ch.id] = now + delay
                await asyncio.to_thread(self._poll_challenge, ch, pane_states)
            except Exception as exc:
                self._record_error(ch.id, exc)
                continue
        if self._round_outputs != self.outputs:
            self.outputs = self._round_outputs
            self.output_revision += 1
        self._round_outputs = {}
        await self._drain_defense_requests()

    async def _drain_defense_requests(self) -> None:
        """触发队列出队给 server 注册的 defense_handler。一路失败不拖垮其余;
        handler 没注册(server 未就绪)也要清空, 队列不跨轮积压。"""
        if not self._defense_requests:
            return
        pending, self._defense_requests = self._defense_requests, []
        if self.defense_handler is None:
            return
        for cid, lines, baseline in pending:
            try:
                await self.defense_handler(cid, lines, baseline)
            except Exception:
                continue

    # ------------------------------------------------------------ per challenge

    def _poll_challenge(self, ch: store.Challenge,
                        pane_states: dict[str, tmuxctl.PaneState] | None = None) -> None:
        dirty = False
        units = store.unit_views(ch)
        for unit in units:
            dirty |= self._poll_unit(ch, unit, pane_states)
            store.apply_unit(ch, unit)   # 旧版单路: 改的是副本, 写回 ch
        if ch.attempts:
            # 多开: 题目状态 = 各路的聚合 (有 flag 则恒 solved)
            new_status = store.aggregate_status(ch)
            if new_status != ch.status:
                ch.status = new_status
                dirty = True
            dirty |= self._poll_board(ch)
            # 漏洞点接力: _poll_board 发现的新 [verified] 漏洞点收进触发队列,
            # 由 poll_once 回到事件循环后 drain (这里在 to_thread 里, 不能 await)
            new_vulns = getattr(ch, "_defense_new", None)
            if new_vulns:
                self._defense_requests.append(
                    (ch.id, new_vulns,
                     getattr(ch, "_defense_baseline", [])))
        if dirty:
            self._save_polled(ch)

    @staticmethod
    def _save_polled(ch: store.Challenge) -> None:
        """合并落盘: 轮询期间用户可能刚通过 PATCH/POST 改了 target/flag/supplements,
        重读磁盘最新 meta 后只覆写监控负责的运行态与黑板字段, 防止旧快照冲掉人工修改。"""
        if ch.meta_path.is_file():
            try:
                latest = store.Challenge.load(ch.meta_path)
            except Exception:
                ch.save()
                return
            if ch.attempts and latest.attempts:
                by_id = {a.get("id"): a for a in ch.attempts}
                for a in latest.attempts:
                    src = by_id.get(a.get("id"))
                    if src:
                        for k in ("status", "exit_seen", "last_output",
                                  "spin_suspected", "idle_at_prompt"):
                            if k in src:
                                a[k] = src[k]
                latest.status = store.aggregate_status(latest)
                for k in ("board_updated", "board_entries", "deliverables",
                          "vuln_points", "defense_feeds", "defense_last_trigger"):
                    setattr(latest, k, getattr(ch, k))
            elif not latest.attempts:
                for k in ("exit_seen", "last_output"):
                    setattr(latest, k, getattr(ch, k))
                if not latest.flag:
                    latest.status = ch.status
            latest.save()
            ch.status = latest.status
        else:
            ch.save()

    def _poll_board(self, ch: store.Challenge) -> bool:
        """统计共享黑板: 条目数 + 内容最后变化的 mtime (卡片上让人不开终端
        也能判断多路之间有没有真在交换证据)。
        顺带提取"可用修补包": 条目里提到 update.tar.gz 且文件真实存在
        (防御路打好包按纪律写板, 这里读板解析, 不做独立的文件轮询)。
        再顺带解析 ## 漏洞点 分区的 [verified] 条目: AWDP+auto_defense 时按
        条目数增长触发防御接力 (_maybe_trigger_defense), 暂存 ch._defense_new
        (瞬态不落 meta), 由 _poll_challenge 收进触发队列。"""
        board = Path(ch.workdir) / "board.md"
        if not board.is_file():
            return False
        try:
            mtime = board.stat().st_mtime
            if mtime == ch.board_updated:
                # 板子没变也可能有冷却期内攒下的漏洞点到期可推
                if (ch.awdp and ch.auto_defense
                        and len(ch.vuln_points) > len(ch.defense_feeds)):
                    self._maybe_trigger_defense(ch, ch.vuln_points)
                    return bool(getattr(ch, "_defense_new", None))
                return False
            content = board.read_text(encoding="utf-8")
            entries = sum(1 for l in content.splitlines()
                          if l.lstrip().startswith("- "))
            deliverables = Monitor._parse_deliverables(ch, content)
            vulns = Monitor._parse_vuln_points(content)
        except OSError:
            return False
        ch.board_updated = mtime
        ch.board_entries = entries
        if deliverables != ch.deliverables:
            ch.deliverables = deliverables
        if vulns != ch.vuln_points:
            ch.vuln_points = vulns
        if ch.awdp and ch.auto_defense:
            self._maybe_trigger_defense(ch, vulns)
        return True

    def _maybe_trigger_defense(self, ch: store.Challenge,
                               vulns: list[str]) -> None:
        """漏洞点接力触发判定。扳机是**条目数增长**, 不是措辞——同一漏洞被
        改写/扩写措辞不该重复推给防御路 (实测同一 nonce 漏洞被改写措辞
        重复推送了三次; 文本相似度又分不开"重写同洞"(0.20)和"同函数不同
        洞"(0.46), 所以宁可漏推不可重复推):
        - 条目数变少: 分区被整理合并过, 重新对齐基线, 不推
        - 条目数不变: 改写, 不推
        - 条目数变多且在冷却期外: 消费整份清单并触发, 推送内容给当前全量
          (防御路自己判断哪些还没修); 冷却期内不消费, 攒到到期一起推"""
        if len(vulns) < len(ch.defense_feeds):
            ch.defense_feeds = list(vulns)
            return
        if len(vulns) == len(ch.defense_feeds):
            return
        cooldown = float(self.config.get("defense_push_cooldown", 180))
        if time.time() - ch.defense_last_trigger < cooldown:
            return
        ch._defense_baseline = list(ch.defense_feeds)   # 留给 Jev 闸门当判据
        ch.defense_feeds = list(vulns)
        ch.defense_last_trigger = time.time()
        ch._defense_new = list(vulns)

    _VULN_VERIFIED_RE = re.compile(
        r"^-\s+(?:\[[^\]]+\]\s*)*\*{0,2}\[verified\]\*{0,2}", re.I
    )
    _FACT_VULN_HINT_RE = re.compile(
        r"漏洞|根因|\bUAF\b|溢出|\bSSTI\b|注入|类型混淆", re.I
    )

    @staticmethod
    def _parse_vuln_points(content: str) -> list[str]:
        """黑板 ## 漏洞点 分区 -> [verified] 条目行原文 (去重保序)。
        兼容 `- [dsh 09:45] [verified]` 或 `- **[verified]**` 等带前缀/粗体写法;
        若 ## 漏洞点 分区尚无条目, 兜底识别 agent 误写在 ## Facts 分区中且明确标注
        漏洞/根因/UAF/溢出/SSTI 的 [verified] 条目 (实测 2026wqbfinal2 多题如此)。"""
        out: list[str] = []
        m = re.search(r"^## 漏洞点[^\n]*\n(.*?)(?=^## |\Z)", content,
                      re.S | re.M)
        if m:
            for line in m.group(1).splitlines():
                line = line.strip()
                if Monitor._VULN_VERIFIED_RE.match(line) and line not in out:
                    out.append(line)
        if out:
            return out
        m_facts = re.search(r"^## Facts[^\n]*\n(.*?)(?=^## |\Z)", content,
                            re.S | re.M)
        if m_facts:
            for line in m_facts.group(1).splitlines():
                line = line.strip()
                if (Monitor._VULN_VERIFIED_RE.match(line)
                        and Monitor._FACT_VULN_HINT_RE.search(line)
                        and line not in out):
                    out.append(line)
        return out

    @staticmethod
    def _parse_deliverables(ch: store.Challenge, content: str) -> list[dict]:
        """黑板 ## 补丁包 分区 -> 可用修补包 [{path, note}]: 条目行 (- 开头) 里
        提到本题修补包文件名 (store.deliverable_name, 以交付模板为准) 的路径,
        且相对题目目录(或绝对路径)能在磁盘上找到。
        只认这一个分区(纪律文件写死了写板位置), 别的分区提到不算数。"""
        m = re.search(r"^## 补丁包[^\n]*\n(.*?)(?=^## |\Z)", content,
                      re.S | re.M)
        if not m:
            return []
        pkg_name = store.deliverable_name(ch)
        name = re.escape(pkg_name)
        out = []
        for line in m.group(1).splitlines():
            line = line.strip()
            if not line.startswith("- ") or pkg_name not in line:
                continue
            for tok in re.findall(rf"[\w./~-]*{name}[\w.-]*", line):
                rel = tok.strip("`'\"，。；")
                p = Path(rel) if rel.startswith("/") else Path(ch.workdir) / rel
                if p.is_file():
                    out.append({"path": rel, "note": line[2:].strip()})
                    break
        return out

    def _poll_unit(self, ch: store.Challenge, unit: dict,
                   pane_states: dict[str, tmuxctl.PaneState] | None = None) -> bool:
        """轮询一路(或旧版单路)的 pane: 退出双保险 / 求助关键词 / 输出快照。"""
        dirty = False

        pane = unit["tmux"].get("pane", "")
        sess = unit["tmux"].get("session", "") or ch.tmux.get("session", "")
        cached_command: str | None = None
        expected_id = unit["tmux"].get("ubz_id", "")
        if pane_states is None:
            # 单测与独立调用保持原行为；正式 poll_once 一定传共享快照。
            alive = bool(pane and tmuxctl.pane_exists(pane, sess, expected_id))
        else:
            state = pane_states.get(pane) if pane else None
            alive = bool(
                state and (not sess or state.session == sess)
                and (not expected_id or state.ubz_id == expected_id)
            )
            cached_command = state.command if alive and state else ""

        def read_current_command() -> str:
            if cached_command is not None:
                return cached_command
            return tmuxctl.pane_current_command(pane)

        if not alive:
            if unit["status"] not in ("pane_gone", "ready", "stopped"):
                unit["status"] = "pane_gone"
                dirty = True
        else:
            try:
                text = tmuxctl.capture(
                    pane, lines=int(self.config.get("capture_lines", 160)))
            except tmuxctl.TmuxError:
                text = ""
            if text:
                # 退出判定双保险:
                #  1) 计数基线: 新出现的独占行 UBZ-EXIT:N (scrollback 旧标记不重复触发)
                #  2) 进程探针: running 但 pane 前台已退回 shell (覆盖手动启动无标记命令的情况)
                count = len(tmuxctl.EXIT_RE.findall(text))
                if count < unit["exit_seen"]:
                    unit["exit_seen"] = count   # 旧标记滚出捕获窗口, 校准基线
                    dirty = True

                if unit["status"] in ("running", "need_help", "solved"):
                    cur = read_current_command()
                    harness_gone = (not cur) or (cur in tmuxctl.SHELL_CMDS)
                    if count > unit["exit_seen"] or harness_gone:
                        unit["exit_seen"] = max(count, unit["exit_seen"])
                        unit["status"] = "exited"
                        dirty = True
                    elif unit["status"] in ("running", "need_help"):
                        asking = self._agent_asking_help(text, unit)
                        new_st = "need_help" if asking else "running"
                        if unit["status"] != new_st:
                            unit["status"] = new_st
                            dirty = True
                elif unit["status"] == "exited":
                    if count > unit["exit_seen"]:
                        # 恢复后又真退出了一次, 记录但保持 exited
                        unit["exit_seen"] = count
                        dirty = True
                    else:
                        # 用户在 pane 里手动拉起了 harness -> 自动回到 running
                        cur = read_current_command()
                        if cur and cur not in tmuxctl.SHELL_CMDS:
                            unit["status"] = "running"
                            dirty = True

                # 空转检测 & 空闲待命检测 (仅多开题的路; 旧版单路 unit 是瞬态包装, 不挂标记):
                # 1) 本地已交付还忙碌 -> Jev 判空转, 亮 🌀 徽章提醒人来停, 不自动打断
                # 2) 进程在跑但停在空闲输入框且无忙碌标志 -> 标 idle_at_prompt, 面板区分"真在干活"与"待命停手"
                if not unit.get("_legacy"):
                    spin = (unit["status"] == "running"
                            and self._looks_spinning(ch, unit, text))
                    if spin != bool(unit.get("spin_suspected")):
                        unit["spin_suspected"] = spin
                        dirty = True
                    idle_p = (unit["status"] == "running"
                              and self._looks_idle_at_prompt(text))
                    if idle_p != bool(unit.get("idle_at_prompt")):
                        unit["idle_at_prompt"] = idle_p
                        dirty = True

                # 只读预览留在内存，不置 dirty、不写 meta；切换 attempt 时用 UUID 索引。
                key = unit["tmux"].get("ubz_id") or unit.get("workdir", "")
                self._round_outputs.setdefault(ch.root, {})[key] = self._tail(text)

        # 终端正文不再持久化到 meta：看板不负责会话回放，实时输出直接在 tmux
        # 查看。只有状态/黑板变化才落盘，避免活跃时每 4 秒写所有题目文件。

        return dirty

    @staticmethod
    def _looks_idle_at_prompt(text: str) -> bool:
        """判断运行中的 TUI 是否已结束本轮执行、停在底部空闲输入框待命。"""
        tail_lines = [l for l in text.rstrip().splitlines() if l.strip()][-12:]
        if not tail_lines or tmuxctl.is_busy(tail_lines):
            return False
        return harness._has_idle_prompt(tail_lines[-8:])

    def _looks_spinning(self, ch: store.Challenge, unit: dict,
                        text: str) -> bool:
        """空转判定 (预筛全免费, 齐了才调 Jev): 还在忙 (状态栏忙碌标志) +
        远程未开 (target 空; 忙着打远程不算) + 本地已交付 (攻击路 flag.txt
        非空 / 防御路已有可用修补包)。每路 spin_check_interval 秒内最多调一次
        Jev; Jev 不可用判否——空转徽章是提醒性质, 宁可不亮不可误亮。"""
        if not self.config.get("jev_spin_gate"):
            return False
        tail = "\n".join(l for l in text.rstrip().splitlines()[-15:]
                         if l.strip())
        if not tmuxctl.is_busy(tail):
            return False
        if ch.target.strip():
            return False
        if unit.get("role") == "defense":
            done = bool(ch.deliverables)
        else:
            try:
                done = bool((Path(unit["workdir"]) / "flag.txt")
                            .read_text(encoding="utf-8").strip())
            except OSError:
                done = False
        if not done:
            return False
        key = unit.get("tmux", {}).get("pane", "") or unit.get("workdir", "")
        now = time.time()
        if (now - self._spin_checked.get(key, 0)
                < float(self.config.get("spin_check_interval", 300))):
            return bool(unit.get("spin_suspected"))   # 保持上次结论
        self._spin_checked[key] = now
        return bool(jevgate.judge_spin(self.config, tail))

    def _agent_asking_help(self, text: str, unit: dict) -> bool:
        """只看最近输出里的 agent 行(TUI 行首 •/⏺); 找不到这类行(非 TUI harness)才看全部。
        cursor/dsh 等会把提示词原样回显成普通行, 所以再剔除注入的 prompt.md 原文行,
        否则 misc 模板自带的"需要人工"会被误判成求助。
        关键词命中后再过 Jev 二审 (jev_help_gate): 真求助/等人介入才算,
        "只是提到这些词"压掉; 判定按屏幕内容哈希缓存, 屏幕不变不重复调 API;
        Jev 不可用回退关键词原判定。"""
        lines = [l for l in text.rstrip().splitlines() if l.strip()]
        tail = lines[-20:]
        agent = [l for l in tail if l.lstrip().startswith(AGENT_LINE_PREFIXES)]
        haystack = "\n".join(agent or tail)
        prompt = self._prompt_text(unit)
        if prompt:
            haystack = "\n".join(
                l for l in haystack.splitlines()
                if l.strip() not in prompt
                and l.strip().lstrip("❯›→>│⌸┃ ").strip() not in prompt
            )
        if not any(k in haystack for k in self.help_keywords):
            return False
        key = unit.get("tmux", {}).get("pane", "") or unit.get("workdir", "")
        h = hash(haystack)
        cached = self._help_verdicts.get(key)
        if cached and cached[0] == h:
            return cached[1]
        verdict = jevgate.judge_help(self.config, haystack)
        if verdict is None:
            verdict = True   # Jev 关了/不可用: 维持关键词原行为
        self._help_verdicts[key] = (h, verdict)
        return verdict

    def _prompt_text(self, unit: dict) -> str:
        """该路注入的 prompt.md 原文 (含多开协作纪律后缀, 按 workdir 缓存)。"""
        workdir = unit.get("workdir", "")
        if workdir not in self._prompt_cache:
            try:
                self._prompt_cache[workdir] = (
                    Path(workdir) / "prompt.md").read_text(encoding="utf-8")
            except OSError:
                self._prompt_cache[workdir] = ""
        return self._prompt_cache[workdir]

    @staticmethod
    def _tail(text: str, n: int = 20) -> str:
        lines = [line.rstrip() for line in text.rstrip().splitlines() if line.strip()]
        return "\n".join(lines[-n:])
