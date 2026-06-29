#!/usr/bin/env bash
# Run all interactive tmux-driven tests
# Intended to be run inside a container (with tmux installed)

set -o nounset
set -o pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# The script under test is staged at $HOME/dev-harden.sh (the Containerfile/CI
# copies it there; helpers.sh derives SCRIPT_PATH from $HOME). Capture it now,
# before we hand each test its own isolated HOME below.
readonly ORIG_SCRIPT="${HOME}/dev-harden.sh"

passed=0
failed=0
total=0

for test_script in "${SCRIPT_DIR}"/test-*.sh; do
    [ -f "$test_script" ] || continue
    total=$((total + 1))
    printf '\n── %s ──\n' "$(basename "$test_script")" >&2

    # Per-test isolation: each test runs in a PRISTINE HOME with its own copy of
    # the script. Without this, tests share one HOME and earlier runs leave the
    # config partially hardened — changing the prompt sequence/timing for later
    # tests and making the accept_until loop race into a free-form prompt
    # (deterministic 3-pass/2-fail). A fresh HOME mirrors running each test
    # alone, where all pass. SSH_AUTH_SOCK is cleared so a vault agent on a dev
    # box can't alter the signing-wizard path (agent signing is covered by BATS).
    test_home="$(mktemp -d)"
    cp "$ORIG_SCRIPT" "${test_home}/dev-harden.sh"
    mkdir -p "${test_home}/.ssh" "${test_home}/.config/git"
    chmod 700 "${test_home}/.ssh"
    if env -u SSH_AUTH_SOCK -u SSH_AGENT_PID \
        HOME="${test_home}" GIT_CONFIG_GLOBAL="${test_home}/.gitconfig" \
        bash "$test_script"; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi
    rm -rf "${test_home}"
done

printf '\n── Interactive tests: %d passed, %d failed, %d total ──\n' "$passed" "$failed" "$total" >&2

if [ "$failed" -gt 0 ]; then
    exit 1
fi
