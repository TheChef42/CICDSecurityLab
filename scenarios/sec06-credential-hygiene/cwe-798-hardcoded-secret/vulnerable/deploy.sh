#!/usr/bin/env sh
set -eu

# FAKE TEST CREDENTIALS ONLY. These values are intentionally invalid.
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export GITHUB_TOKEN="ghp_FAKE1234567890abcdefghijklmnop"
export STRIPE_KEY="sk_test_FAKE1234567890abcdef"

echo "Deploying with fake test credentials for scanner demonstration only."
