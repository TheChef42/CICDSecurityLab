#!/usr/bin/env sh
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ARTIFACT="${1:-$SCRIPT_DIR/artifact.txt}"
PROVENANCE="${2:-$SCRIPT_DIR/provenance.json}"
TRUSTED_BUILDER="https://ci.example.invalid/trusted-builder"

if [ ! -f "$PROVENANCE" ]; then
  echo "Missing provenance; refusing deployment." >&2
  exit 1
fi

EXPECTED_SHA256="$(node -e "const fs=require('fs'); const p=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); console.log(p.subject.sha256)" "$PROVENANCE")"
ACTUAL_SHA256="$(sha256sum "$ARTIFACT" | awk '{print $1}')"
BUILDER_ID="$(node -e "const fs=require('fs'); const p=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); console.log(p.builder.id)" "$PROVENANCE")"

if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
  echo "Artifact digest mismatch; refusing deployment." >&2
  exit 1
fi

if [ "$BUILDER_ID" != "$TRUSTED_BUILDER" ]; then
  echo "Untrusted builder identity; refusing deployment." >&2
  exit 1
fi

echo "Provenance verified; deploying $ARTIFACT."
