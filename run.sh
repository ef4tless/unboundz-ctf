#!/usr/bin/env bash
# ubz-ctf 启动脚本
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
fi
# 本地机密 (API key 等) 放 ~/.ubz-ctf/env, 不进 repo
if [ -f ~/.ubz-ctf/env ]; then
  set -a; . ~/.ubz-ctf/env; set +a
fi
exec .venv/bin/python server.py
