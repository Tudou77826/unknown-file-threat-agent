#!/usr/bin/env bash
set -euo pipefail

# Edit these values to run a different case or model.
CASE_NAME="c2_malicious"
MODE="deepagents"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
CASE_DIR="$SCRIPT_DIR/cases/$CASE_NAME"
OUTPUT_DIR="$SCRIPT_DIR/outputs/${CASE_NAME}_agent"

if [[ -x ".venv/Scripts/python.exe" ]]; then
  PYTHON_BIN=".venv/Scripts/python.exe"
elif [[ -x ".venv/bin/python" ]]; then
  PYTHON_BIN=".venv/bin/python"
else
  echo "Project virtual environment not found. Run 'uv sync --extra dev' in $SCRIPT_DIR." >&2
  exit 1
fi

"$PYTHON_BIN" -m threat_agent.cli \
  --case "$CASE_DIR" \
  --mode "$MODE" \
  --output "$OUTPUT_DIR"
