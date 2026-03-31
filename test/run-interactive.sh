#!/usr/bin/env bash
# Run interactive tmux tests on the host in an isolated HOME.
# Covers macOS ssh-keygen and platform-specific behavior that
# cannot be tested inside Linux containers.
#
# Requires: tmux, git, ssh-keygen

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT

die() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

# Check dependencies
command -v tmux >/dev/null 2>&1 || die "tmux is required. Install with: brew install tmux"
command -v git >/dev/null 2>&1 || die "git is required"
command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is required"

# Create isolated HOME
TEST_HOME="$(mktemp -d)"
trap 'rm -rf "$TEST_HOME"' EXIT

# Set up the isolated environment
export HOME="$TEST_HOME"
export GIT_CONFIG_GLOBAL="${TEST_HOME}/.gitconfig"

mkdir -p "${TEST_HOME}/.ssh"
mkdir -p "${TEST_HOME}/.config/git"

# Copy the script into the test home (interactive helpers expect it at ~/git-harden.sh)
cp "${REPO_ROOT}/git-harden.sh" "${TEST_HOME}/git-harden.sh"

# Copy interactive test scripts
cp -r "${SCRIPT_DIR}/interactive" "${TEST_HOME}/test-interactive"

# Set up minimal git config
git config --global user.name "Test User"
git config --global user.email "test@example.com"

printf '── Running interactive tests on host (%s) ──\n' "$(uname -s)" >&2

# Run the interactive tests
exec bash "${TEST_HOME}/test-interactive/run-all.sh"
