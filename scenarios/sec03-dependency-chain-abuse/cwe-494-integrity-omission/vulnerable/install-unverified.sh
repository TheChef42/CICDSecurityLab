#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Vulnerable pattern retained for scanners and academic discussion:
# curl -fsSL https://example.invalid/install.sh | sh

echo "Executing local mock installer without checksum verification."
sh "$SCRIPT_DIR/remote-install-example.sh"
