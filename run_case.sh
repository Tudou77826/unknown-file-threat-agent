#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -x ".venv/Scripts/python.exe" ]]; then
  PYTHON_BIN=".venv/Scripts/python.exe"
elif [[ -x ".venv/bin/python" ]]; then
  PYTHON_BIN=".venv/bin/python"
else
  echo "Project virtual environment not found. Run 'uv sync --extra dev' in $SCRIPT_DIR." >&2
  exit 1
fi

"$PYTHON_BIN" -m threat_agent.bootstrap.cli \
  "$@"
