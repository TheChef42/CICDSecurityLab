#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARTIFACT="${1:-$SCRIPT_DIR/artifact.txt}"
ALLOW_MISSING_PROVENANCE=true

if [ "$ALLOW_MISSING_PROVENANCE" = "true" ]; then
  echo "Deploying $ARTIFACT without provenance verification."
fi
