#!/usr/bin/env bash
# Shared helpers for interactive tmux-driven tests

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

TMUX_SESSION="test-$$"
readonly SCRIPT_PATH="${HOME}/dev-harden.sh"

# Colors
if [ -t 2 ]; then
    readonly C_RED='\033[0;31m'
    readonly C_GREEN='\033[0;32m'
    readonly C_RESET='\033[0m'
else
    readonly C_RED=''
    readonly C_GREEN=''
    readonly C_RESET=''
fi

# Wait for a string to appear in the tmux pane.
# Polls every 0.2s, times out after $2 seconds (default 10).
wait_for() {
    local pattern="$1"
    local timeout="${2:-10}"
    local elapsed=0
    while ! tmux capture-pane -t "$TMUX_SESSION" -p | grep -qF "$pattern"; do
        sleep 0.2
        elapsed=$(( elapsed + 1 ))
        if (( elapsed > timeout * 5 )); then
            printf 'TIMEOUT waiting for: %s\n' "$pattern" >&2
            printf 'Current pane content:\n' >&2
            tmux capture-pane -t "$TMUX_SESSION" -p >&2
            return 1
        fi
    done
}

# Send keys to the tmux session
send() {
    tmux send-keys -t "$TMUX_SESSION" "$@"
}

# Start dev-harden.sh in a tmux session.
# Explicitly pass HOME and GIT_CONFIG_GLOBAL — tmux spawns a login shell
# which resets HOME from the passwd entry, breaking the isolated test env.
start_session() {
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
    sleep 0.5
    local env_setup="export HOME='${HOME}';"
    if [ -n "${GIT_CONFIG_GLOBAL:-}" ]; then
        env_setup="${env_setup} export GIT_CONFIG_GLOBAL='${GIT_CONFIG_GLOBAL}';"
    fi
    tmux new-session -d -s "$TMUX_SESSION" \
        "${env_setup} bash '${SCRIPT_PATH}'"
    # Keep the pane alive after the script exits so capture_output can read it
    tmux set-option -t "$TMUX_SESSION" remain-on-exit on
    sleep 0.5
    # Verify session started
    if ! tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
        printf 'ERROR: tmux session "%s" failed to start\n' "$TMUX_SESSION" >&2
        printf 'SCRIPT_PATH=%s\n' "$SCRIPT_PATH" >&2
        printf 'HOME=%s\n' "$HOME" >&2
        return 1
    fi
}

# Wait for the script to exit and capture final output
capture_output() {
    # Wait for the shell to become available (script exited)
    local timeout=30
    local elapsed=0
    while tmux list-panes -t "$TMUX_SESSION" -F '#{pane_dead}' 2>/dev/null | grep -q '^0$'; do
        sleep 0.5
        elapsed=$(( elapsed + 1 ))
        if (( elapsed > timeout * 2 )); then
            printf 'TIMEOUT waiting for script to exit\n' >&2
            tmux capture-pane -t "$TMUX_SESSION" -p >&2
            return 1
        fi
    done
    tmux capture-pane -t "$TMUX_SESSION" -p
}

# Clean up
cleanup() {
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
}

# Assert helper
assert_contains() {
    local haystack="$1"
    local needle="$2"
    if printf '%s' "$haystack" | grep -qF "$needle"; then
        return 0
    fi
    printf '%bFAIL:%b expected output to contain: %s\n' "$C_RED" "$C_RESET" "$needle" >&2
    return 1
}

# Accept all [Y/n] prompts until a stop pattern appears in the pane.
# Usage: accept_until "Signing key options" [max_iterations]
accept_until() {
    local stop_pattern="$1"
    local max_iters="${2:-80}"
    local pane_content last_content=""
    local i
    for ((i = 0; i < max_iters; i++)); do
        pane_content="$(tmux capture-pane -t "$TMUX_SESSION" -p 2>/dev/null || true)"
        if printf '%s' "$pane_content" | grep -qF "$stop_pattern"; then
            return 0
        fi
        if printf '%s' "$pane_content" | grep -qF "Hardening complete"; then
            return 0
        fi
        # Only send "y" when a new prompt has appeared (pane changed and shows [Y/n])
        if [ "$pane_content" != "$last_content" ] \
            && printf '%s' "$pane_content" | grep -qE '\[Y/n\]|\[y/N\]'; then
            send "y" Enter
            last_content="$pane_content"
            sleep 0.3
        else
            sleep 0.2
        fi
    done
}

pass() {
    printf '%b  PASS:%b %s\n' "$C_GREEN" "$C_RESET" "$1" >&2
}

fail() {
    printf '%b  FAIL:%b %s\n' "$C_RED" "$C_RESET" "$1" >&2
}
