#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TOOL="trivy"
RAW_FILE="$RAW_DIR/trivy.json"
LOG_FILE="$LOG_DIR/trivy.log"
RAW_REF="results/raw/trivy.json"

if ! command -v trivy >/dev/null 2>&1; then
  write_diag "$TOOL" "ERROR" "Trivy is not installed in the scanner image." "" ""
  exit 0
fi

set +e
trivy fs \
  --format json \
  --output "$RAW_FILE" \
  --exit-code 0 \
  --scanners vuln,misconfig,secret \
  --skip-dirs "$RESULTS_DIR" \
  --skip-dirs "$PROJECT_DIR/node_modules" \
  --skip-dirs "$PROJECT_DIR/web/node_modules" \
  "$PROJECT_DIR" >"$LOG_FILE" 2>&1
CODE=$?
set -u

if [ "$CODE" -eq 0 ]; then
  write_diag "$TOOL" "OK" "Trivy filesystem scan completed." "$RAW_REF" "$(tail_log "$LOG_FILE")"
else
  write_diag "$TOOL" "WARN" "Trivy exited with code $CODE; normalization will use any raw output that was produced." "$RAW_REF" "$(tail_log "$LOG_FILE")"
fi

exit 0
