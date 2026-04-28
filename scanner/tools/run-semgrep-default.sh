#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TOOL="semgrep-default"
RAW_FILE="$RAW_DIR/semgrep-default.json"
LOG_FILE="$LOG_DIR/semgrep-default.log"
RAW_REF="results/raw/semgrep-default.json"

if ! command -v semgrep >/dev/null 2>&1; then
  write_diag "$TOOL" "ERROR" "Semgrep is not installed in the scanner image." "" ""
  exit 0
fi

set +e
semgrep scan \
  --metrics=off \
  --config p/default \
  --json \
  --output "$RAW_FILE" \
  --exclude results \
  --exclude node_modules \
  --exclude web/node_modules \
  "$PROJECT_DIR" >"$LOG_FILE" 2>&1
CODE=$?
set -u

if [ "$CODE" -eq 0 ]; then
  write_diag "$TOOL" "OK" "Semgrep default rules scan completed." "$RAW_REF" "$(tail_log "$LOG_FILE")"
else
  write_diag "$TOOL" "WARN" "Semgrep default rules scan exited with code $CODE; this may require network access to fetch registry rules." "$RAW_REF" "$(tail_log "$LOG_FILE")"
fi

exit 0
