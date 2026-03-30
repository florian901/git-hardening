#!/usr/bin/env bash
# Run the BATS test suite
set -o errexit
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
"${SCRIPT_DIR}/libs/bats-core/bin/bats" "${SCRIPT_DIR}/git-harden.bats" "$@"
