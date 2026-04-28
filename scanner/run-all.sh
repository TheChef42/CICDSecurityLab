#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-/workspace}"
RESULTS_DIR="${RESULTS_DIR:-$PROJECT_DIR/results}"
RAW_DIR="$RESULTS_DIR/raw"
NORMALIZED_DIR="$RESULTS_DIR/normalized"
DIAGNOSTICS_DIR="$RAW_DIR/diagnostics"

mkdir -p "$RAW_DIR" "$NORMALIZED_DIR" "$DIAGNOSTICS_DIR"

node "$SCRIPT_DIR/init-results.js"

echo "Running CI/CD security lab scanners against $PROJECT_DIR"

for tool in trivy semgrep gitleaks checkov grype snyk; do
  echo "---- $tool ----"
  bash "$SCRIPT_DIR/tools/run-$tool.sh" || true
done

echo "---- normalize ----"
node "$SCRIPT_DIR/normalize-results.js"

echo "Scanner run complete. Results are in $RESULTS_DIR"
