#!/usr/bin/env sh
set -eu

# FAKE TEST CREDENTIALS ONLY. These values are intentionally invalid.
export AWS_ACCESS_KEY_ID="AKIAI53GZYXMPQR8UVWX"
export GITHUB_TOKEN="ghp_4xK9mN2pQr7sT1uV3wY6zA8bC0dE5fGhJ"
export STRIPE_KEY="sk_test_FAKE1234567890abcdef"

echo "Deploying with fake test credentials for scanner demonstration only."
