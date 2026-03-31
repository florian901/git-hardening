#!/usr/bin/env bash
# Run all interactive tmux-driven tests
# Intended to be run inside a container (with tmux installed)

set -o nounset
set -o pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

passed=0
failed=0
total=0

for test_script in "${SCRIPT_DIR}"/test-*.sh; do
    [ -f "$test_script" ] || continue
    total=$((total + 1))
    printf '\n── %s ──\n' "$(basename "$test_script")" >&2
    if bash "$test_script"; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi
done

printf '\n── Interactive tests: %d passed, %d failed, %d total ──\n' "$passed" "$failed" "$total" >&2

if [ "$failed" -gt 0 ]; then
    exit 1
fi
