#!/usr/bin/env bash
# Interactive test: identity guard prevents useConfigOnly lockout
# Verifies: when user.name/email are missing, the script prompts for them
# before enabling useConfigOnly; after providing both, useConfigOnly is set.

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "${SCRIPT_DIR}/helpers.sh"

main() {
    trap cleanup EXIT

    printf 'Test: Identity guard — missing name/email\n' >&2

    # Remove identity AND useConfigOnly so the guard triggers
    git config --global --unset user.name 2>/dev/null || true
    git config --global --unset user.email 2>/dev/null || true
    git config --global --unset user.useConfigOnly 2>/dev/null || true

    # Remove signing keys so wizard shows options (not existing key prompt)
    rm -f "${HOME}/.ssh/id_ed25519_signing" "${HOME}/.ssh/id_ed25519_signing.pub"
    rm -f "${HOME}/.ssh/id_ed25519" "${HOME}/.ssh/id_ed25519.pub"

    start_session

    # Safety review gate
    wait_for "reviewed this script"
    send "y" Enter

    # Proceed with hardening
    wait_for "Proceed with hardening"
    send "y" Enter

    # Accept settings until identity guard prompt appears
    local pane_content
    for _ in $(seq 1 50); do
        sleep 0.3
        pane_content="$(tmux capture-pane -t "$TMUX_SESSION" -p 2>/dev/null || true)"
        if printf '%s' "$pane_content" | grep -qF "Enter your name"; then
            break
        fi
        if printf '%s' "$pane_content" | grep -qF "Hardening complete"; then
            fail "Identity guard did not trigger — reached completion"
            exit 1
        fi
        send "y" Enter
    done

    # Identity guard: enter name
    wait_for "Enter your name" 15
    send "Test User" Enter

    # Identity guard: enter email
    wait_for "Enter your email" 10
    send "test@example.com" Enter

    # Continue accepting remaining prompts
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

    # Skip signing
    if tmux capture-pane -t "$TMUX_SESSION" -p | grep -qF "Signing key options"; then
        send "s" Enter
    fi

    # Wait for completion
    sleep 2
    capture_output >/dev/null 2>&1 || true

    # Verify: useConfigOnly was set
    local use_config_only
    use_config_only="$(git config --global --get user.useConfigOnly 2>/dev/null || true)"
    if [ "$use_config_only" = "true" ]; then
        pass "Identity guard: useConfigOnly=true set after providing name/email"
    else
        fail "Identity guard: useConfigOnly not set (expected true, got '${use_config_only}')"
        exit 1
    fi

    # Verify: name and email were set
    local name email
    name="$(git config --global --get user.name 2>/dev/null || true)"
    email="$(git config --global --get user.email 2>/dev/null || true)"
    if [ "$name" = "Test User" ] && [ "$email" = "test@example.com" ]; then
        pass "Identity guard: user.name and user.email configured"
    else
        fail "Identity guard: identity not configured (name='${name}', email='${email}')"
        exit 1
    fi
}

main
