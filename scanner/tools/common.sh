#!/usr/bin/env bash

PROJECT_DIR="${PROJECT_DIR:-/workspace}"
RESULTS_DIR="${RESULTS_DIR:-$PROJECT_DIR/results}"
RAW_DIR="$RESULTS_DIR/raw"
DIAGNOSTICS_DIR="$RAW_DIR/diagnostics"
LOG_DIR="$RAW_DIR/logs"

mkdir -p "$RAW_DIR" "$DIAGNOSTICS_DIR" "$LOG_DIR"

write_diag() {
  local tool="$1"
  local status="$2"
  local message="$3"
  local raw_path="${4:-}"
  local details="${5:-}"
  local diag_file="$DIAGNOSTICS_DIR/$tool.json"

  node -e '
const fs = require("fs");
const [file, tool, status, message, rawPath, details] = process.argv.slice(1);
const payload = {
  tool,
  status,
  message,
  rawOutputPath: rawPath || null
};
if (details) payload.details = details.slice(0, 8000);
fs.writeFileSync(file, JSON.stringify(payload, null, 2));
' "$diag_file" "$tool" "$status" "$message" "$raw_path" "$details"
}

tail_log() {
  local file="$1"
  if [ -f "$file" ]; then
    tail -n 80 "$file" 2>/dev/null || true
  fi
}
