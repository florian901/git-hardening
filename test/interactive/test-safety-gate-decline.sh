#!/usr/bin/env bash
# Interactive test: decline safety review gate
# Verifies: script exits 0, prints AI review instructions, no config changes

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "${SCRIPT_DIR}/helpers.sh"

main() {
    trap cleanup EXIT

    printf 'Test: Safety gate decline\n' >&2

    # Snapshot current config
    local config_before
    config_before="$(git config --global --list 2>/dev/null || true)"

    start_session

    # Safety review gate — answer no (default)
    wait_for "reviewed this script"
    send "n" Enter

    # Wait for exit
    sleep 2
    local output
    output="$(capture_output)"

    # Verify: output contains AI review instructions
    assert_contains "$output" "claude"
    assert_contains "$output" "gemini"

    # Verify: no config changes
    local config_after
    config_after="$(git config --global --list 2>/dev/null || true)"
    if [ "$config_before" = "$config_after" ]; then
        pass "Safety gate decline: no config changes, instructions shown"
    else
        fail "Safety gate decline: config was modified"
        exit 1
    fi
}

main
