#!/usr/bin/env bash
# Interactive test: generate ed25519 key via signing wizard
# Verifies: key created, user.signingkey configured, commit.gpgsign=true

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "${SCRIPT_DIR}/helpers.sh"

main() {
    trap cleanup EXIT

    printf 'Test: Signing wizard - generate ed25519 key\n' >&2

    # Ensure identity is set (prior tests may have cleared it)
    git config --global user.name "Test User" 2>/dev/null || true
    git config --global user.email "test@example.com" 2>/dev/null || true

    # Ensure no existing signing keys (new dedicated names + legacy)
    rm -f "${HOME}/.ssh/id_ed25519_signing" "${HOME}/.ssh/id_ed25519_signing.pub"
    rm -f "${HOME}/.ssh/id_ed25519" "${HOME}/.ssh/id_ed25519.pub"

    start_session

    # Safety review gate
    wait_for "reviewed this script"
    send "y" Enter

    # Proceed with hardening
    wait_for "Proceed with hardening"
    send "y" Enter

    # Accept all [Y/n] prompts until signing wizard
    accept_until "Signing key options"

    # Signing wizard — option 1: generate ed25519
    wait_for "Signing key options" 20
    send "1" Enter

    # ssh-keygen prompts for passphrase — enter empty twice
    wait_for "Enter passphrase" 10
    send "" Enter
    wait_for "Enter same passphrase" 10
    send "" Enter

    # Signing wizard asks "Enable commit and tag signing?" — accept
    wait_for "Enable commit and tag signing" 10
    send "y" Enter

    # Wait for completion
    sleep 3
    capture_output >/dev/null 2>&1 || true

    # Verify key exists (new dedicated signing key name)
    if [ -f "${HOME}/.ssh/id_ed25519_signing.pub" ]; then
        pass "Key generated: ~/.ssh/id_ed25519_signing.pub exists"
    else
        fail "Key not generated"
        exit 1
    fi

    # Verify signing key configured
    local signing_key
    signing_key="$(git config --global --get user.signingkey 2>/dev/null || true)"
    if [ -n "$signing_key" ]; then
        pass "user.signingkey configured: ${signing_key}"
    else
        fail "user.signingkey not configured"
        exit 1
    fi

    # Verify gpgsign enabled
    local gpgsign
    gpgsign="$(git config --global --get commit.gpgsign 2>/dev/null || true)"
    if [ "$gpgsign" = "true" ]; then
        pass "commit.gpgsign=true"
    else
        fail "commit.gpgsign not set"
        exit 1
    fi
}

main
