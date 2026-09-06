# ubz-ctf

CTF 协作层：Web 界面创建题目，自动下载附件、在 tmux 里开 pane 启动 codex/claude 并注入分类提示词，后台监控运行状态与求助信号。

## 启动

```bash
./run.sh          # 首次自动建 venv 装依赖
# 打开 http://127.0.0.1:8600
```

## 使用

1. 首次打开先点顶部设置**赛事根目录**（如 `~/ctf/2026qwb`），不存在可勾选创建。
2. 「新建题目」：填名称、选类型（web/pwn/re/misc/crypto/custom）、题目信息、目标地址，附件支持**下载链接**（每行一个）和**本地上传**（多选，压缩包自动解压）两种方式，可混用；选 harness，默认创建后立即启动。
3. 每题在 tmux session `ctf-<赛事名>` 里占一个 pane，全部 pane 平铺在**同一个 window** 里（attach 进去一屏看到所有 agent；想恢复"每 window 4 pane 满了开新 window"把 `panes_per_window` 改成 4 即可）。
4. 仪表盘每 3s 刷新：misc 出现求助关键词标橙；进程退出标红可一键恢复（`codex resume --last` / `claude -c`）；在 pane 里手动拉起 harness 会自动回 running。
5. 「✉ 消息」直接往 agent 的 pane 追加指令；「⌨ 终端」接管该题——优先把**已 attach 的现有终端**（本赛事 session 上的 client 优先，否则最近活跃的 client）switch-client 切过去；没有可用 client 时才在 gnome-terminal 里开标签页；「📎 附件」解题中途补传文件；「⚑ flag」手动登记 flag 并标记已解出。
7. **靶机后补**：建题时靶机可留空（web/pwn 卡片显示「待靶机」）。环境开放后点卡片上的 🎯 行，填入地址后可「保存并发送」——自动往 agent 的 pane 发一条补充消息（文案可编辑），同时 prompt.md 重渲染、补充记录进 meta 的 supplements。agent 不在运行时会拒绝发送（防止消息被 shell 当命令执行），信息照常保存。

## 结构

- 每题目录：`meta.json`（状态事实源）、`prompt.md`（渲染后的提示词）、`attachments/`、`flag.txt`（agent 回写）
- `prompts/*.md`：分类模板，直接编辑生效；变量 `{题目信息} {靶机地址} {远程地址} {目标} {题目名称} {工作目录} {附件清单}`
- `config.yaml`：harness 命令、求助关键词、终端类型、分屏策略等
- `~/.ubz-ctf/state.json`：当前/最近赛事根目录
