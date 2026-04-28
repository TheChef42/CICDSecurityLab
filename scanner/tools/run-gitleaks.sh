#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TOOL="gitleaks"
RAW_FILE="$RAW_DIR/gitleaks.json"
LOG_FILE="$LOG_DIR/gitleaks.log"
RAW_REF="results/raw/gitleaks.json"

if ! command -v gitleaks >/dev/null 2>&1; then
  write_diag "$TOOL" "ERROR" "Gitleaks is not installed in the scanner image." "" ""
  exit 0
fi

set +e
gitleaks dir "$PROJECT_DIR" \
  --report-format json \
  --report-path "$RAW_FILE" \
  --exit-code 0 \
  --redact=20 >"$LOG_FILE" 2>&1
CODE=$?
set -u

if [ "$CODE" -eq 0 ]; then
  write_diag "$TOOL" "OK" "Gitleaks repository scan completed." "$RAW_REF" "$(tail_log "$LOG_FILE")"
else
  write_diag "$TOOL" "WARN" "Gitleaks exited with code $CODE; normalization will use any raw output that was produced." "$RAW_REF" "$(tail_log "$LOG_FILE")"
fi

exit 0
