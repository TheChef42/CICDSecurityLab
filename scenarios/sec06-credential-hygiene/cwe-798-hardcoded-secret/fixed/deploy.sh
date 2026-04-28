#!/usr/bin/env sh
set -eu

: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID must be supplied by the environment}"
: "${GITHUB_TOKEN:?GITHUB_TOKEN must be supplied by the environment}"
: "${STRIPE_KEY:?STRIPE_KEY must be supplied by the environment}"

echo "Deploying with credentials supplied by the runtime environment."
