#!/usr/bin/env bash
# Interactive test: skip signing wizard
# Verifies: no signing key configured, commit.gpgsign not set

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "${SCRIPT_DIR}/helpers.sh"

main() {
    trap cleanup EXIT

    printf 'Test: Signing wizard - skip\n' >&2

    # Remove any keys from prior tests so wizard shows key generation options
    rm -f "${HOME}/.ssh/id_ed25519" "${HOME}/.ssh/id_ed25519.pub"
    rm -f "${HOME}/.ssh/id_ed25519_sk" "${HOME}/.ssh/id_ed25519_sk.pub"
    git config --global --unset user.signingkey 2>/dev/null || true
    git config --global --unset commit.gpgsign 2>/dev/null || true

    start_session

    # Safety review gate
    wait_for "reviewed this script"
    send "y" Enter

    # Proceed with hardening
    wait_for "Proceed with hardening"
    send "y" Enter

    # Accept settings until signing wizard (v0.2.0 adds more prompts)
    local pane_content
    for _ in $(seq 1 50); do
        sleep 0.3
        pane_content="$(tmux capture-pane -t "$TMUX_SESSION" -p 2>/dev/null || true)"
        if printf '%s' "$pane_content" | grep -qF "Signing key options"; then
            break
        fi
        if printf '%s' "$pane_content" | grep -qF "Hardening complete"; then
            break
        fi
        send "y" Enter
    done

    # Signing wizard — skip
    wait_for "Signing key options" 20
    send "s" Enter

    # Wait for completion
    sleep 2
    capture_output >/dev/null 2>&1 || true

    # Verify: no signing key
    local signing_key
    signing_key="$(git config --global --get user.signingkey 2>/dev/null || true)"
    if [ -z "$signing_key" ]; then
        pass "Signing skip: user.signingkey not set"
    else
        fail "Signing skip: user.signingkey was set unexpectedly: ${signing_key}"
        exit 1
    fi

    # Verify: commit.gpgsign not set
    local gpgsign
    gpgsign="$(git config --global --get commit.gpgsign 2>/dev/null || true)"
    if [ -z "$gpgsign" ]; then
        pass "Signing skip: commit.gpgsign not set"
    else
        fail "Signing skip: commit.gpgsign was set unexpectedly: ${gpgsign}"
        exit 1
    fi
}

main
