#!/usr/bin/env bash
# Start the API (port 8765) and the triage console (port 4317) together.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${ROOT}/.venv/bin/python"
[ -x "$PY" ] || PY=python3

export SOC_LLM_BACKEND="${SOC_LLM_BACKEND:-auto}"

(cd "$ROOT/backend" && exec "$PY" -m uvicorn soc_copilot.api:app --host 127.0.0.1 --port "${API_PORT:-8765}") &
API_PID=$!
trap 'kill $API_PID 2>/dev/null' EXIT

cd "$ROOT/frontend" && npm run dev -- --port "${WEB_PORT:-4317}"
