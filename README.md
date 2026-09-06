# ubz-ctf

面向多题并行 CTF 的本地任务面板：通过 Web 界面建立题目，为每题分配 tmux pane，启动 Codex/Claude、注入分类提示词，并集中查看运行状态与人工求助信号。

## 启动

```bash
./run.sh          # 首次自动建 venv 装依赖
# 打开 http://127.0.0.1:8600
```

## 使用

1. 首次打开先点顶部设置**赛事根目录**（如 `~/ctf/2026qwb`），不存在可勾选创建。
2. 「新建题目」：填名称、选类型（web/pwn/re/misc/crypto/custom）、题目信息、目标地址，附件支持**下载链接**（每行一个）和**本地上传**（多选，压缩包自动解压）两种方式，可混用；选 harness，默认创建后立即启动。
3. 每题在 tmux session `ctf-<赛事名>` 里占一个 pane。默认每个 window 放 4 个 pane 并采用 tiled 布局，满后自动新建 window；把 `config.yaml` 中的 `panes_per_window` 设为 `0`，可改为所有 pane 平铺在同一个 window。
4. Web 面板每 3 秒刷新，后台 monitor 默认每 4 秒检查一次 pane。输出中出现配置的求助关键词时标橙；进程退出或 pane 消失时标红，并提供恢复入口。在 pane 中手动重新启动 harness 后，状态会自动回到「解题中」。
5. 「⌨ 终端」用于接管该题：优先复用已 attach 的终端 client；没有可用 client 时，才由配置的终端模拟器打开标签页或窗口。「📎 附件」用于在解题过程中补传文件。
6. 「⚑ flag」用于手动登记、修改或删除最终 flag。保存非空 flag 后题目标记为「已解出」；清空输入并保存会撤销「已解出」，再根据 pane 的实际状态显示为「解题中」「进程退出」「窗口丢失」或「就绪」。
7. **靶机后补**：建题时靶机可留空（Web/Pwn 卡片显示「待靶机」）。环境开放后点击卡片上的 🎯 行，可只保存地址，也可把可编辑的补充消息发送给正在运行的 agent；同时会重新渲染 `prompt.md`，并把消息写入 `meta.json` 的 `supplements`。agent 未运行时只保存信息，不把文本发送给 shell。

## 结构

- 每题目录：`meta.json`（状态事实源）、`prompt.md`（渲染后的提示词）、`attachments/`、`flag.txt`（agent 回写）
- `prompts/*.md`：分类模板，直接编辑生效；变量 `{题目信息} {靶机地址} {远程地址} {目标} {题目名称} {工作目录} {附件清单}`
- `config.yaml`：harness 命令、求助关键词、终端类型、分屏策略等
- `~/.ubz-ctf/state.json`：当前/最近赛事根目录
