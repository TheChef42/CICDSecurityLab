#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TOOL="semgrep-custom"
RAW_FILE="$RAW_DIR/semgrep-custom.json"
LOG_FILE="$LOG_DIR/semgrep-custom.log"
RAW_REF="results/raw/semgrep-custom.json"
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
  write_diag "$TOOL" "OK" "Semgrep custom lab rules scan completed." "$RAW_REF" "$(tail_log "$LOG_FILE")"
else
  write_diag "$TOOL" "ERROR" "Semgrep custom lab rules scan failed with code $CODE." "$RAW_REF" "$(tail_log "$LOG_FILE")"
fi

exit 0
