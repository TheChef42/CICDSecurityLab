#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TOOL="semgrep"
RAW_FILE="$RAW_DIR/semgrep.json"
LOG_FILE="$LOG_DIR/semgrep.log"
RAW_REF="results/raw/semgrep.json"
LOCAL_RULES="$PROJECT_DIR/scanner/semgrep-rules.yml"

if ! command -v semgrep >/dev/null 2>&1; then
  write_diag "$TOOL" "ERROR" "Semgrep is not installed in the scanner image." "" ""
  exit 0
fi

set +e
semgrep scan \
  --metrics=off \
  --config "$LOCAL_RULES" \
  --json \
  --output "$RAW_FILE" \
  --exclude results \
  --exclude node_modules \
  --exclude web/node_modules \
  "$PROJECT_DIR" >"$LOG_FILE" 2>&1
CODE=$?
set -u

if [ "$CODE" -eq 0 ]; then
  write_diag "$TOOL" "OK" "Semgrep scan completed with local lab rules." "$RAW_REF" "$(tail_log "$LOG_FILE")"
else
  write_diag "$TOOL" "ERROR" "Semgrep failed with code $CODE." "$RAW_REF" "$(tail_log "$LOG_FILE")"
fi

exit 0
