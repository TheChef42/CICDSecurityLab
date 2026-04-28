#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARTIFACT="$SCRIPT_DIR/trusted-install.sh"
CHECKSUM_FILE="$SCRIPT_DIR/trusted-install.sh.sha256"

EXPECTED_SHA256="$(awk '{print $1}' "$CHECKSUM_FILE")"
ACTUAL_SHA256="$(sha256sum "$ARTIFACT" | awk '{print $1}')"

if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  echo "Checksum verification failed; refusing to execute artifact." >&2
  exit 1
fi

echo "Checksum verified; executing trusted local artifact."
sh "$ARTIFACT"
