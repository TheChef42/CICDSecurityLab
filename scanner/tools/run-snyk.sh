#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

TOOL="snyk"
RAW_FILE="$RAW_DIR/snyk.json"
LOG_FILE="$LOG_DIR/snyk.log"
RAW_REF="results/raw/snyk.json"

if [ -z "${SNYK_TOKEN:-}" ]; then
  write_diag "$TOOL" "WARN" "SNYK_TOKEN is not set; Snyk scan skipped." "" ""
  exit 0
fi

if ! command -v snyk >/dev/null 2>&1; then
  write_diag "$TOOL" "ERROR" "Snyk CLI is not installed in the scanner image." "" ""
  exit 0
fi

SNYK_ARGS_BASE=(
  --all-projects
  --detection-depth=8
  --exclude=results,node_modules
  --json-file-output="$RAW_FILE"
)

run_snyk() {
  local log_mode="$1"
  shift
  set +e
  if [ "$log_mode" = "append" ]; then
    snyk test "$PROJECT_DIR" "$@" >>"$LOG_FILE" 2>&1
  else
    snyk test "$PROJECT_DIR" "$@" >"$LOG_FILE" 2>&1
  fi
  local code=$?
  set -u
  return "$code"
}

SNYK_ARGS=("${SNYK_ARGS_BASE[@]}")
USED_ORG="false"

if [ -n "${SNYK_ORG:-}" ]; then
  SNYK_ARGS+=(--org="$SNYK_ORG")
  USED_ORG="true"
fi

run_snyk "write" "${SNYK_ARGS[@]}"
CODE=$?

if [ "$CODE" -eq 2 ] && [ "$USED_ORG" = "true" ] && grep -q "Org .* was not found" "$LOG_FILE"; then
  {
    echo
    echo "Retrying Snyk without SNYK_ORG because the configured org was not found or is not accessible."
  } >>"$LOG_FILE"
  run_snyk "append" "${SNYK_ARGS_BASE[@]}"
  CODE=$?
fi

case "$CODE" in
  0)
    write_diag "$TOOL" "OK" "Snyk scan completed with no reported vulnerabilities." "$RAW_REF" "$(tail_log "$LOG_FILE")"
    ;;
  1)
    write_diag "$TOOL" "OK" "Snyk scan completed and reported findings." "$RAW_REF" "$(tail_log "$LOG_FILE")"
    ;;
  3)
    write_diag "$TOOL" "WARN" "Snyk found no supported projects to scan." "$RAW_REF" "$(tail_log "$LOG_FILE")"
    ;;
  *)
    write_diag "$TOOL" "WARN" "Snyk exited with code $CODE; normalization will use any raw output that was produced." "$RAW_REF" "$(tail_log "$LOG_FILE")"
    ;;
esac

exit 0
