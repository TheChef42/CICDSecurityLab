#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TOOL="grype"
RAW_FILE="$RAW_DIR/grype.json"
LOG_FILE="$LOG_DIR/grype.log"
RAW_REF="results/raw/grype.json"

if ! command -v grype >/dev/null 2>&1; then
  write_diag "$TOOL" "ERROR" "Grype is not installed in the scanner image." "" ""
  exit 0
fi

set +e
START_MS="$(now_ms)"
grype "dir:$PROJECT_DIR" \
  -o json \
  --exclude "./results" \
  --exclude "./web/node_modules" \
  >"$RAW_FILE" 2>"$LOG_FILE"
CODE=$?
RUNTIME_MS="$(elapsed_ms "$START_MS")"
set -u

if [ "$CODE" -eq 0 ]; then
  write_diag "$TOOL" "OK" "Grype filesystem vulnerability scan completed." "$RAW_REF" "$(tail_log "$LOG_FILE")" "$RUNTIME_MS"
else
  write_diag "$TOOL" "WARN" "Grype exited with code $CODE; normalization will use any raw output that was produced." "$RAW_REF" "$(tail_log "$LOG_FILE")" "$RUNTIME_MS"
fi

exit 0
