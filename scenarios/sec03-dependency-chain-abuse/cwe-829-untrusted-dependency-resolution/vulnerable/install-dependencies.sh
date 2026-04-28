#!/usr/bin/env sh
set -eu

# Vulnerable for CI: resolves dependency ranges because no package-lock.json is present.
npm install
