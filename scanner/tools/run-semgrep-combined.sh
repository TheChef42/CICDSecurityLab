#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TOOL="semgrep-combined"
RAW_FILE="$RAW_DIR/semgrep-combined.json"
LOG_FILE="$LOG_DIR/semgrep-combined.log"
RAW_REF="results/raw/semgrep-combined.json"
LOCAL_RULES="$PROJECT_DIR/scanner/semgrep-rules.yml"
SEMGREP_BIN="$(command -v semgrep || true)"

if [ -z "$SEMGREP_BIN" ] && [ -x /opt/semgrep/bin/semgrep ]; then
  SEMGREP_BIN="/opt/semgrep/bin/semgrep"
fi

if [ -z "$SEMGREP_BIN" ]; then
  printf '{"version":"unknown","results":[],"errors":[]}\n' >"$RAW_FILE"
  write_diag "$TOOL" "ERROR" "Semgrep is not installed in the scanner image." "" ""
  exit 0
fi

set +e
"$SEMGREP_BIN" scan \
  --metrics=off \
  --config p/default \
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
  write_diag "$TOOL" "OK" "Semgrep combined default and custom rules scan completed." "$RAW_REF" "$(tail_log "$LOG_FILE")"
else
  write_diag "$TOOL" "WARN" "Semgrep combined scan exited with code $CODE; this may require network access to fetch registry rules." "$RAW_REF" "$(tail_log "$LOG_FILE")"
fi

exit 0
