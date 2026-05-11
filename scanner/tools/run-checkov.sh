#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TOOL="checkov"
RAW_FILE="$RAW_DIR/checkov.json"
LOG_FILE="$LOG_DIR/checkov.log"
RAW_REF="results/raw/checkov.json"

if ! command -v checkov >/dev/null 2>&1; then
  write_diag "$TOOL" "ERROR" "Checkov is not installed in the scanner image." "" ""
  exit 0
fi

set +e
START_MS="$(now_ms)"
CKV_IGNORE_HIDDEN_DIRECTORIES=false checkov \
  --directory "$PROJECT_DIR" \
  --output json \
  --soft-fail \
  --skip-download \
  --skip-path "$RESULTS_DIR" \
  --skip-path "$PROJECT_DIR/node_modules" \
  --skip-path "$PROJECT_DIR/web/node_modules" \
  >"$RAW_FILE" 2>"$LOG_FILE"
CODE=$?
RUNTIME_MS="$(elapsed_ms "$START_MS")"
set -u

if [ "$CODE" -eq 0 ]; then
  write_diag "$TOOL" "OK" "Checkov IaC/configuration scan completed." "$RAW_REF" "$(tail_log "$LOG_FILE")" "$RUNTIME_MS"
else
  write_diag "$TOOL" "WARN" "Checkov exited with code $CODE; normalization will use any raw output that was produced." "$RAW_REF" "$(tail_log "$LOG_FILE")" "$RUNTIME_MS"
fi

exit 0
