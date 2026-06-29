#!/usr/bin/env bats

# dev-harden.sh — BATS test suite
# Runs in an isolated HOME to avoid touching real config.

BATS_TEST_DIRNAME="$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)"
SCRIPT="${BATS_TEST_DIRNAME}/../dev-harden.sh"

load 'libs/bats-support/load'
load 'libs/bats-assert/load'

# ---------------------------------------------------------------------------
# Test isolation: every test gets its own HOME, GIT_CONFIG, SSH_DIR
# ---------------------------------------------------------------------------

setup() {
    TEST_HOME="$(mktemp -d)"
    export HOME="$TEST_HOME"
    export GIT_CONFIG_GLOBAL="${TEST_HOME}/.gitconfig"

    # Isolate from any ambient SSH agent on the test host: agent detection
    # reads these, and a real agent's keys would otherwise leak into the
    # isolated-HOME fixtures. Tests that exercise agents set them explicitly.
    unset SSH_AUTH_SOCK SSH_CONNECTION SSH_TTY GPG_AGENT_INFO
    # Point gpg at an empty sandbox dir so gpgconf cannot report a live
    # host gpg-agent ssh socket into the agent detection path.
    export GNUPGHOME="${TEST_HOME}/.gnupg"

    mkdir -p "${TEST_HOME}/.ssh"
    mkdir -p "${TEST_HOME}/.config/git"
    mkdir -p "${TEST_HOME}/.gnupg"
    chmod 700 "${TEST_HOME}/.gnupg"

    # Ensure git has user.name/email so config operations work
    git config --global user.name "Test User"
    git config --global user.email "test@example.com"
}

teardown() {
    # Reap any throwaway ssh-agent started for an agent test.
    if [ -n "${TEST_AGENT_PID:-}" ]; then
        kill "$TEST_AGENT_PID" 2>/dev/null || true
        unset TEST_AGENT_PID
    fi
    if [ -n "${TEST_AGENT_SOCK:-}" ]; then
        rm -f "$TEST_AGENT_SOCK"
        unset TEST_AGENT_SOCK
    fi
    rm -rf "$TEST_HOME"
}

# Helper: source the script's functions without running main()
# We replace main() with a no-op so we can call functions individually.
source_functions() {
    # Disable errexit so we can test error paths
    set +o errexit
    # Override main and readonly to allow re-sourcing
    eval "$(sed 's/^main "\$@"$//' "$SCRIPT" | sed 's/^readonly //' | sed '/^set -o errexit/d; /^set -o nounset/d; /^set -o pipefail/d; /^IFS=/d')"
    set -o errexit
}

# Start a throwaway ssh-agent inside the test sandbox and export SSH_AUTH_SOCK
# pointing at it. Records the PID in TEST_AGENT_PID so teardown can reap it.
# CI needs no vault products: we generate a key, load it, then delete the
# private file to prove the no-on-disk path.
start_test_agent() {
    # Unix domain socket paths are capped (~104 bytes on macOS). bats' mktemp
    # HOME is long, so bind the agent to a short, dedicated path instead of
    # letting ssh-agent derive one under $TMPDIR/$HOME.
    TEST_AGENT_SOCK="$(mktemp -u "${TMPDIR:-/tmp}/gh-a.XXXX")"
    local agent_out
    agent_out="$(ssh-agent -s -a "$TEST_AGENT_SOCK")"
    eval "$agent_out" >/dev/null
    TEST_AGENT_PID="$SSH_AGENT_PID"
    export SSH_AUTH_SOCK="$TEST_AGENT_SOCK"
}

# ===========================================================================
# Argument parsing
# ===========================================================================

@test "--help prints usage and exits 0" {
    run bash "$SCRIPT" --help
    assert_success
    assert_output --partial "Usage: dev-harden.sh"
}

@test "-h prints usage and exits 0" {
    run bash "$SCRIPT" -h
    assert_success
    assert_output --partial "Usage: dev-harden.sh"
}

@test "--version prints version and exits 0" {
    run bash "$SCRIPT" --version
    assert_success
    assert_output --partial "dev-harden.sh"
    assert_output --partial "0.8.0"
}

@test "unknown option exits 1" {
    run bash "$SCRIPT" --bogus
    assert_failure
    assert_output --partial "Unknown option"
}

# ===========================================================================
# Version comparison (version_gte)
# ===========================================================================

@test "version_gte: equal versions" {
    source_functions
    run version_gte "2.34.0" "2.34.0"
    assert_success
}

@test "version_gte: higher major" {
    source_functions
    run version_gte "3.0.0" "2.34.0"
    assert_success
}

@test "version_gte: higher minor" {
    source_functions
    run version_gte "2.40.0" "2.34.0"
    assert_success
}

@test "version_gte: higher patch" {
    source_functions
    run version_gte "2.34.1" "2.34.0"
    assert_success
}

@test "version_gte: lower version fails" {
    source_functions
    run version_gte "2.33.9" "2.34.0"
    assert_failure
}

@test "version_gte: lower minor fails" {
    source_functions
    run version_gte "2.20.0" "2.34.0"
    assert_failure
}

@test "version_gte: handles leading zeros without octal error" {
    source_functions
    run version_gte "2.08.0" "2.07.0"
    assert_success
}

@test "version_gte: leading zero comparison works correctly" {
    source_functions
    run version_gte "2.09.1" "2.09.0"
    assert_success
}

# ===========================================================================
# Version extraction (grep-based, not sed)
# ===========================================================================

@test "version extraction handles standard git output" {
    local ver
    ver="$(echo "git version 2.39.5" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    [ "$ver" = "2.39.5" ]
}

@test "version extraction handles Apple Git suffix" {
    local ver
    ver="$(echo "git version 2.39.5 (Apple Git-154)" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    [ "$ver" = "2.39.5" ]
}

@test "version extraction handles rc suffix" {
    local ver
    ver="$(echo "git version 2.45.0-rc1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    [ "$ver" = "2.45.0" ]
}

# ===========================================================================
# strip_ssh_value helper
# ===========================================================================

@test "strip_ssh_value removes inline comment" {
    source_functions
    local result
    result="$(strip_ssh_value "~/.ssh/id_ed25519 # signing key")"
    [ "$result" = "~/.ssh/id_ed25519" ]
}

@test "strip_ssh_value removes surrounding double quotes" {
    source_functions
    local result
    result="$(strip_ssh_value '"~/.ssh/my key"')"
    [ "$result" = "~/.ssh/my key" ]
}

@test "strip_ssh_value removes quotes and comment together" {
    source_functions
    local result
    result="$(strip_ssh_value '"~/.ssh/my key" # comment')"
    [ "$result" = "~/.ssh/my key" ]
}

@test "strip_ssh_value handles plain value" {
    source_functions
    local result
    result="$(strip_ssh_value "accept-new")"
    [ "$result" = "accept-new" ]
}

# ===========================================================================
# Audit: git config settings
# ===========================================================================

@test "audit reports MISS for unconfigured setting" {
    source_functions
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_git_setting "transfer.fsckObjects" "true"
    assert_output --partial "[MISS]"
}

@test "audit reports OK for correctly configured setting" {
    git config --global transfer.fsckObjects true

    source_functions
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_git_setting "transfer.fsckObjects" "true"
    assert_output --partial "[OK]"
}

@test "audit reports WARN for wrong value" {
    git config --global transfer.fsckObjects false

    source_functions
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_git_setting "transfer.fsckObjects" "true"
    assert_output --partial "[WARN]"
}

# ===========================================================================
# Audit: credential helper
# ===========================================================================

@test "audit warns on credential.helper=store" {
    git config --global credential.helper store

    source_functions
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_git_config
    assert_output --partial "INSECURE"
    assert_output --partial "plaintext"
}

# ===========================================================================
# Audit: pull.rebase conflict warning
# ===========================================================================

@test "audit warns when pull.rebase conflicts with pull.ff=only" {
    git config --global pull.rebase true

    source_functions
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_git_config
    assert_output --partial "pull.rebase"
    assert_output --partial "conflicts"
}

# ===========================================================================
# Audit: signing
# ===========================================================================

@test "audit reports MISS when no signing key configured" {
    source_functions
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_signing
    assert_output --partial "[MISS]"
    assert_output --partial "user.signingkey"
}

@test "audit reports OK for valid signing key file" {
    # Create a fake key file
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q
    git config --global user.signingkey "${TEST_HOME}/.ssh/id_ed25519.pub"
    git config --global gpg.format ssh
    git config --global gpg.ssh.allowedSignersFile "~/.config/git/allowed_signers"
    git config --global commit.gpgsign true
    git config --global tag.gpgsign true
    git config --global tag.forceSignAnnotated true

    source_functions
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_signing
    assert_output --partial "[OK]"
    refute_output --partial "[MISS]"
}

@test "audit handles inline SSH key" {
    git config --global user.signingkey "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake"

    source_functions
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_signing
    assert_output --partial "inline key"
}

@test "audit warns for signing key pointing to missing file" {
    git config --global user.signingkey "/nonexistent/key.pub"

    source_functions
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_signing
    assert_output --partial "[WARN]"
    assert_output --partial "file not found"
}

# ===========================================================================
# Audit: SSH config
# ===========================================================================

@test "audit reports MISS when SSH config missing" {
    rm -f "${TEST_HOME}/.ssh/config"

    source_functions
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_ssh_config
    assert_output --partial "[MISS]"
    assert_output --partial "does not exist"
}

@test "audit reports OK for correct SSH directives" {
    cat > "${TEST_HOME}/.ssh/config" <<'SSHEOF'
StrictHostKeyChecking accept-new
HashKnownHosts yes
IdentitiesOnly yes
AddKeysToAgent yes
PubkeyAcceptedAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com
SSHEOF

    source_functions
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_ssh_config
    # Should have 5 OK and no MISS
    refute_output --partial "[MISS]"
    refute_output --partial "[WARN]"
}

@test "audit reports WARN for wrong SSH directive value" {
    cat > "${TEST_HOME}/.ssh/config" <<'SSHEOF'
StrictHostKeyChecking yes
SSHEOF

    source_functions
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_ssh_directive "StrictHostKeyChecking" "accept-new"
    assert_output --partial "[WARN]"
}

# ===========================================================================
# Audit report & exit codes
# ===========================================================================

@test "audit report returns 0 when all OK" {
    source_functions
    AUDIT_OK=5; AUDIT_WARN=0; AUDIT_MISS=0

    run print_audit_report
    assert_success
    assert_output --partial "5 OK"
}

@test "audit report returns 2 when issues found" {
    source_functions
    AUDIT_OK=3; AUDIT_WARN=1; AUDIT_MISS=2

    run print_audit_report
    assert_failure 2
    assert_output --partial "1 WARN"
    assert_output --partial "2 MISS"
}

# ===========================================================================
# Apply: git config settings (-y mode)
# ===========================================================================

@test "-y mode applies setting group" {
    source_functions
    AUTO_YES=true

    run apply_setting_group "Test Group" "Test description" \
        "transfer.fsckObjects" "true" "Verify objects on transfer"
    assert_success

    local result
    result="$(git config --global --get transfer.fsckObjects)"
    [ "$result" = "true" ]
}

@test "apply_setting_group skips already-correct settings" {
    git config --global transfer.fsckObjects true

    source_functions
    AUTO_YES=true

    run apply_setting_group "Test Group" "Test description" \
        "transfer.fsckObjects" "true" "Verify objects on transfer"
    assert_success
    # No changes needed — group should not print "Applied"
    refute_output --partial "Applied"
}

# ===========================================================================
# Apply: full git config (-y mode, end-to-end)
# ===========================================================================

@test "-y mode applies all hardening settings" {
    source_functions
    AUTO_YES=true
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"

    run apply_git_config
    assert_success

    # Verify a sampling of the applied settings
    [ "$(git config --global transfer.fsckObjects)" = "true" ]
    [ "$(git config --global protocol.allow)" = "never" ]
    [ "$(git config --global protocol.https.allow)" = "always" ]
    [ "$(git config --global protocol.ext.allow)" = "never" ]
    [ "$(git config --global core.protectNTFS)" = "true" ]
    [ "$(git config --global core.protectHFS)" = "true" ]
    [ "$(git config --global core.fsmonitor)" = "false" ]
    [ "$(git config --global safe.bareRepository)" = "explicit" ]
    [ "$(git config --global submodule.recurse)" = "false" ]
    [ "$(git config --global pull.ff)" = "only" ]
    [ "$(git config --global merge.ff)" = "only" ]
    [ "$(git config --global http.sslVerify)" = "true" ]
    [ "$(git config --global log.showSignature)" = "true" ]
    [ "$(git config --global credential.helper)" = "osxkeychain" ]
}

@test "-y mode applies url.https rewrite" {
    source_functions
    AUTO_YES=true
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"

    apply_git_config

    local result
    result="$(git config --global --get 'url.https://.insteadOf')"
    [ "$result" = "http://" ]
}

# ===========================================================================
# Apply: SSH config
# ===========================================================================

@test "apply creates SSH dir and config with correct permissions" {
    rm -rf "${TEST_HOME}/.ssh"

    source_functions
    AUTO_YES=true

    apply_ssh_config

    # Check directory exists with correct mode
    [ -d "${TEST_HOME}/.ssh" ]
    [ -f "${TEST_HOME}/.ssh/config" ]

    # stat format differs: macOS uses -f '%Lp', Linux uses -c '%a'
    local dir_perms
    if stat -f '%Lp' "${TEST_HOME}/.ssh" >/dev/null 2>&1; then
        dir_perms="$(stat -f '%Lp' "${TEST_HOME}/.ssh")"
    else
        dir_perms="$(stat -c '%a' "${TEST_HOME}/.ssh")"
    fi
    [ "$dir_perms" = "700" ]

    local file_perms
    if stat -f '%Lp' "${TEST_HOME}/.ssh/config" >/dev/null 2>&1; then
        file_perms="$(stat -f '%Lp' "${TEST_HOME}/.ssh/config")"
    else
        file_perms="$(stat -c '%a' "${TEST_HOME}/.ssh/config")"
    fi
    [ "$file_perms" = "600" ]
}

@test "apply adds SSH directives to empty config" {
    : > "${TEST_HOME}/.ssh/config"

    source_functions
    AUTO_YES=true

    run apply_ssh_config
    assert_success

    # Verify directives were added
    grep -q "StrictHostKeyChecking accept-new" "${TEST_HOME}/.ssh/config"
    grep -q "HashKnownHosts yes" "${TEST_HOME}/.ssh/config"
    grep -q "IdentitiesOnly yes" "${TEST_HOME}/.ssh/config"
    grep -q "AddKeysToAgent yes" "${TEST_HOME}/.ssh/config"
}

@test "apply skips SSH directives that already exist with correct value" {
    cat > "${TEST_HOME}/.ssh/config" <<'SSHEOF'
StrictHostKeyChecking accept-new
SSHEOF

    source_functions
    AUTO_YES=true

    apply_single_ssh_directive "StrictHostKeyChecking" "accept-new"

    # Should still have exactly one occurrence
    local count
    count="$(grep -c "StrictHostKeyChecking" "${TEST_HOME}/.ssh/config")"
    [ "$count" -eq 1 ]
}

@test "apply updates SSH directive with wrong value" {
    cat > "${TEST_HOME}/.ssh/config" <<'SSHEOF'
Host *
    StrictHostKeyChecking yes
    HashKnownHosts no
SSHEOF

    source_functions
    AUTO_YES=true

    apply_single_ssh_directive "StrictHostKeyChecking" "accept-new"

    # Verify updated
    grep -q "StrictHostKeyChecking accept-new" "${TEST_HOME}/.ssh/config"
    # Old value should be gone
    ! grep -q "StrictHostKeyChecking yes" "${TEST_HOME}/.ssh/config"
    # Other directives should be preserved
    grep -q "HashKnownHosts no" "${TEST_HOME}/.ssh/config"
}

@test "audit recognises SSH directives using = separator" {
    source_functions

    cat > "${TEST_HOME}/.ssh/config" <<'SSHEOF'
StrictHostKeyChecking=accept-new
HashKnownHosts = yes
SSHEOF

    run audit_ssh_directive "StrictHostKeyChecking" "accept-new"
    assert_output --partial "[OK]"

    run audit_ssh_directive "HashKnownHosts" "yes"
    assert_output --partial "[OK]"
}

@test "apply skips SSH directives using = separator when value matches" {
    cat > "${TEST_HOME}/.ssh/config" <<'SSHEOF'
StrictHostKeyChecking=accept-new
SSHEOF

    source_functions
    AUTO_YES=true

    apply_single_ssh_directive "StrictHostKeyChecking" "accept-new"

    # Should still have exactly one occurrence
    local count
    count="$(grep -c "StrictHostKeyChecking" "${TEST_HOME}/.ssh/config")"
    [ "$count" -eq 1 ]
}

# ===========================================================================
# Signing: key detection
# ===========================================================================

@test "detect_existing_keys finds ed25519 key" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = true ]
    [ "$SIGNING_PUB_PATH" = "${TEST_HOME}/.ssh/id_ed25519.pub" ]
}

@test "detect_existing_keys prefers dedicated signing key over general key" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519_signing" -N "" -q

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = true ]
    [ "$SIGNING_PUB_PATH" = "${TEST_HOME}/.ssh/id_ed25519_signing.pub" ]
}

@test "detect_existing_keys prefers sk signing key over software key" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q
    # Fake an sk signing key (can't generate real one without hardware)
    cp "${TEST_HOME}/.ssh/id_ed25519" "${TEST_HOME}/.ssh/id_ed25519_sk_signing"
    # Write a fake pub key with sk type prefix
    printf 'sk-ssh-ed25519@openssh.com AAAAFakeKey test\n' > "${TEST_HOME}/.ssh/id_ed25519_sk_signing.pub"

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = true ]
    [ "$SIGNING_PUB_PATH" = "${TEST_HOME}/.ssh/id_ed25519_sk_signing.pub" ]
}

@test "detect_existing_keys finds key from IdentityFile directive" {
    # Create a key with a non-standard name
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/my_custom_key" -N "" -q

    cat > "${TEST_HOME}/.ssh/config" <<SSHEOF
Host github.com
    IdentityFile ${TEST_HOME}/.ssh/my_custom_key
SSHEOF

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = true ]
    [ "$SIGNING_PUB_PATH" = "${TEST_HOME}/.ssh/my_custom_key.pub" ]
}

@test "detect_existing_keys handles IdentityFile with inline comment" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/my_key" -N "" -q

    cat > "${TEST_HOME}/.ssh/config" <<SSHEOF
Host github.com
    IdentityFile ${TEST_HOME}/.ssh/my_key # signing key
SSHEOF

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = true ]
    [ "$SIGNING_PUB_PATH" = "${TEST_HOME}/.ssh/my_key.pub" ]
}

@test "detect_existing_keys handles quoted IdentityFile path" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/my_key" -N "" -q

    cat > "${TEST_HOME}/.ssh/config" <<SSHEOF
Host github.com
    IdentityFile "${TEST_HOME}/.ssh/my_key"
SSHEOF

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = true ]
    [ "$SIGNING_PUB_PATH" = "${TEST_HOME}/.ssh/my_key.pub" ]
}

@test "detect_existing_keys finds configured key via user.signingkey" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/signing_key" -N "" -q
    git config --global user.signingkey "${TEST_HOME}/.ssh/signing_key.pub"

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = true ]
    [ "$SIGNING_PUB_PATH" = "${TEST_HOME}/.ssh/signing_key.pub" ]
}

@test "detect_existing_keys handles tilde in user.signingkey" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q
    git config --global user.signingkey "~/.ssh/id_ed25519.pub"

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = true ]
}

@test "detect_existing_keys reports not found when no keys exist" {
    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = false ]
    [ -z "$SIGNING_PUB_PATH" ]
}

# ===========================================================================
# Signing: allowed signers
# ===========================================================================

@test "setup_allowed_signers creates file and adds entry" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q

    source_functions
    SIGNING_PUB_PATH="${TEST_HOME}/.ssh/id_ed25519.pub"

    run setup_allowed_signers
    assert_success

    [ -f "${TEST_HOME}/.config/git/allowed_signers" ]
    grep -q "test@example.com" "${TEST_HOME}/.config/git/allowed_signers"
    grep -q "ssh-ed25519" "${TEST_HOME}/.config/git/allowed_signers"
}

@test "setup_allowed_signers is idempotent" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q

    source_functions
    SIGNING_PUB_PATH="${TEST_HOME}/.ssh/id_ed25519.pub"

    setup_allowed_signers
    setup_allowed_signers

    local count
    count="$(wc -l < "${TEST_HOME}/.config/git/allowed_signers" | tr -d ' ')"
    [ "$count" -eq 1 ]
}

@test "setup_allowed_signers skips when no email provided" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q
    git config --global --unset user.email

    source_functions
    SIGNING_PUB_PATH="${TEST_HOME}/.ssh/id_ed25519.pub"

    # In non-interactive context, read from /dev/tty fails — empty email
    run setup_allowed_signers
    assert_output --partial "No email provided"
}

# ===========================================================================
# Signing: -y mode behavior
# ===========================================================================

@test "-y mode enables signing when key exists" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q

    source_functions
    AUTO_YES=true

    run apply_signing_config
    assert_success

    [ "$(git config --global commit.gpgsign)" = "true" ]
    [ "$(git config --global tag.gpgsign)" = "true" ]
    [ "$(git config --global gpg.format)" = "ssh" ]
}

@test "-y mode skips signing enablement when no key exists" {
    source_functions
    AUTO_YES=true

    run apply_signing_config
    assert_success
    assert_output --partial "No SSH signing key found"

    # gpg.format should be set (non-breaking)
    [ "$(git config --global gpg.format)" = "ssh" ]
    # But commit.gpgsign should NOT be set
    local gpgsign
    gpgsign="$(git config --global --get commit.gpgsign 2>/dev/null || true)"
    [ -z "$gpgsign" ]
}

# ===========================================================================
# Backup
# ===========================================================================

@test "backup creates timestamped file" {
    git config --global transfer.fsckObjects true

    source_functions

    run backup_git_config
    assert_success
    assert_output --partial "Config backed up"

    # Verify backup file exists and contains config
    local backup_file
    backup_file="$(ls "${TEST_HOME}/.config/git"/pre-harden-backup-*.txt 2>/dev/null | head -1)"
    [ -n "$backup_file" ]
    grep -q "transfer.fsckobjects=true" "$backup_file"
}

# ===========================================================================
# Safety review gate
# ===========================================================================

@test "safety gate is skipped with -y" {
    source_functions
    AUTO_YES=true
    AUDIT_ONLY=false

    run safety_review_gate
    assert_success
    refute_output --partial "Safety Review"
}

@test "safety gate is skipped with --audit" {
    source_functions
    AUTO_YES=false
    AUDIT_ONLY=true

    run safety_review_gate
    assert_success
    refute_output --partial "Safety Review"
}

@test "safety gate exits 0 with instructions when user says no" {
    source_functions
    AUTO_YES=false
    AUDIT_ONLY=false

    # Override prompt_yn to simulate "no" answer
    prompt_yn() { return 1; }

    run safety_review_gate
    assert_success  # exit 0, not an error
    assert_output --partial "claude"
    assert_output --partial "gemini"
}

# ===========================================================================
# End-to-end: --audit mode
# ===========================================================================

@test "--audit exits 2 on fresh config" {
    run bash "$SCRIPT" --audit
    assert_failure 2
    assert_output --partial "MISS"
}

@test "--audit exits 0 when fully hardened" {
    # Apply all settings first
    bash "$SCRIPT" -y 2>/dev/null

    run bash "$SCRIPT" --audit
    # May still exit 2 if SSH config or signing isn't fully set up,
    # but git config settings should be OK
    assert_output --partial "[OK]"
}

# ===========================================================================
# End-to-end: -y mode
# ===========================================================================

@test "-y mode runs without prompts and applies config" {
    run bash "$SCRIPT" -y
    assert_success
    assert_output --partial "Hardening complete"

    # Spot-check a few settings
    [ "$(git config --global transfer.fsckObjects)" = "true" ]
    [ "$(git config --global protocol.allow)" = "never" ]
    [ "$(git config --global pull.ff)" = "only" ]
}

@test "-y mode is idempotent" {
    bash "$SCRIPT" -y 2>/dev/null

    run bash "$SCRIPT" -y
    assert_success
    # Should still succeed on second run
    assert_output --partial "Hardening complete"
}

# ===========================================================================
# Platform detection
# ===========================================================================

@test "detect_platform sets PLATFORM" {
    source_functions
    detect_platform

    # We're running on macOS or Linux
    [[ "$PLATFORM" = "macos" || "$PLATFORM" = "linux" ]]
}

# ===========================================================================
# Admin recommendations (smoke test)
# ===========================================================================

@test "admin recommendations print without error" {
    source_functions
    run print_admin_recommendations
    assert_success
    # Always-present, non-signing org guidance. The signing-specific items
    # (vigilant mode, require-signed-commits) are gated on a configured signing
    # key and covered by their own tests.
    assert_output --partial "branch protection"
}

# ===========================================================================
# v0.2.0: New git config settings
# ===========================================================================

@test "audit reports new v0.2.0 settings as MISS on fresh config" {
    source_functions
    detect_platform
    detect_credential_helper

    run audit_git_config
    assert_output --partial "user.useConfigOnly"
    assert_output --partial "transfer.bundleURI"
    assert_output --partial "fetch.prune"
    assert_output --partial "protocol.version"
    assert_output --partial "init.defaultBranch"
    assert_output --partial "gc.reflogExpire"
    assert_output --partial "gc.reflogExpireUnreachable"
    assert_output --partial "core.symlinks"
}

@test "-y mode applies new v0.2.0 settings" {
    run bash "$SCRIPT" -y
    assert_success

    [ "$(git config --global user.useConfigOnly)" = "true" ]
    [ "$(git config --global transfer.bundleURI)" = "false" ]
    [ "$(git config --global fetch.prune)" = "true" ]
    [ "$(git config --global protocol.version)" = "2" ]
    [ "$(git config --global init.defaultBranch)" = "main" ]
    [ "$(git config --global gc.reflogExpire)" = "180.days" ]
    [ "$(git config --global gc.reflogExpireUnreachable)" = "90.days" ]
}

@test "-y mode does NOT apply core.symlinks" {
    run bash "$SCRIPT" -y
    assert_success

    local symlinks
    symlinks="$(git config --global --get core.symlinks 2>/dev/null || echo "unset")"
    [ "$symlinks" = "unset" ]
}

# ===========================================================================
# v0.2.0: safe.directory wildcard detection
# ===========================================================================

@test "audit detects safe.directory = * wildcard" {
    source_functions
    detect_platform
    detect_credential_helper

    git config --global safe.directory '*'

    run audit_git_config
    assert_output --partial "safe.directory = * disables ownership checks"
}

@test "audit does not warn without safe.directory wildcard" {
    source_functions
    detect_platform
    detect_credential_helper

    git config --global safe.directory "/some/path"

    run audit_git_config
    refute_output --partial "safe.directory = * disables"
}

@test "-y mode removes safe.directory = * wildcard" {
    git config --global safe.directory '*'

    run bash "$SCRIPT" -y
    assert_success

    local safe_dirs
    safe_dirs="$(git config --global --get-all safe.directory 2>/dev/null || echo "none")"
    refute [ "$safe_dirs" = "*" ]
}

# ===========================================================================
# v0.2.0: Pre-commit hook
# ===========================================================================

@test "audit reports MISS when no pre-commit hook exists" {
    source_functions

    run audit_precommit_hook
    assert_output --partial "No pre-commit hook"
}

@test "audit reports OK when gitleaks hook exists" {
    source_functions

    mkdir -p "${HOME}/.config/git/hooks"
    cat > "${HOME}/.config/git/hooks/pre-commit" << 'EOF'
#!/usr/bin/env bash
gitleaks protect --staged
EOF
    chmod +x "${HOME}/.config/git/hooks/pre-commit"

    run audit_precommit_hook
    assert_output --partial "[OK]"
    assert_output --partial "gitleaks"
}

@test "audit reports WARN for non-gitleaks hook" {
    source_functions

    mkdir -p "${HOME}/.config/git/hooks"
    printf '#!/usr/bin/env bash\necho custom hook\n' > "${HOME}/.config/git/hooks/pre-commit"
    chmod +x "${HOME}/.config/git/hooks/pre-commit"

    run audit_precommit_hook
    assert_output --partial "does not reference gitleaks"
}

@test "apply does not overwrite existing pre-commit hook" {
    source_functions
    AUTO_YES=true

    mkdir -p "${HOME}/.config/git/hooks"
    printf '#!/usr/bin/env bash\necho my hook\n' > "${HOME}/.config/git/hooks/pre-commit"

    run apply_precommit_hook
    assert_output --partial "not overwriting"

    # Verify original content preserved
    run cat "${HOME}/.config/git/hooks/pre-commit"
    assert_output --partial "my hook"
}

# ===========================================================================
# v0.2.0: Global gitignore
# ===========================================================================

@test "audit reports MISS when no excludesFile configured" {
    source_functions

    run audit_global_gitignore
    assert_output --partial "no global gitignore configured"
}

@test "audit reports OK when excludesFile has security patterns" {
    source_functions

    mkdir -p "${HOME}/.config/git"
    printf '.env\n*.pem\n*.key\n' > "${HOME}/.config/git/ignore"
    git config --global core.excludesFile "~/.config/git/ignore"

    run audit_global_gitignore
    assert_output --partial "[OK]"
    assert_output --partial "contains security patterns"
}

@test "audit warns when excludesFile lacks security patterns" {
    source_functions

    mkdir -p "${HOME}/.config/git"
    printf '*.log\n*.tmp\n' > "${HOME}/.config/git/ignore"
    git config --global core.excludesFile "~/.config/git/ignore"

    run audit_global_gitignore
    assert_output --partial "lacks secret patterns"
}

@test "-y mode creates global gitignore" {
    run bash "$SCRIPT" -y
    assert_success

    [ -f "${HOME}/.config/git/ignore" ]
    run cat "${HOME}/.config/git/ignore"
    assert_output --partial ".env"
    assert_output --partial "*.pem"
    assert_output --partial "*.key"
    assert_output --partial "!.env.example"

    [ "$(git config --global core.excludesFile)" = "~/.config/git/ignore" ]
}

@test "-y mode skips gitignore when excludesFile already set" {
    git config --global core.excludesFile "/some/other/path"

    run bash "$SCRIPT" -y
    assert_success

    [ "$(git config --global core.excludesFile)" = "/some/other/path" ]
}

# ===========================================================================
# v0.2.0 / v0.8 Phase 1: Secret inventory (folds in old credential hygiene)
# ===========================================================================

@test "secret inventory warns about ~/.git-credentials" {
    source_functions

    printf 'https://user:token@github.com\n' > "${HOME}/.git-credentials"

    run audit_secret_inventory
    assert_output --partial ".git-credentials"
    assert_output --partial "git credentials"
}

@test "secret inventory warns about ~/.netrc" {
    source_functions

    printf 'machine github.com\nlogin user\npassword token\n' > "${HOME}/.netrc"

    run audit_secret_inventory
    assert_output --partial ".netrc"
}

@test "secret inventory warns about ~/.npmrc with auth token" {
    source_functions

    printf '//registry.npmjs.org/:_authToken=npm_abcdef123456\n' > "${HOME}/.npmrc"

    run audit_secret_inventory
    assert_output --partial "npm token"
}

@test "secret inventory does not warn about ~/.npmrc without token" {
    source_functions

    printf 'registry=https://registry.npmjs.org/\n' > "${HOME}/.npmrc"

    run audit_secret_inventory
    refute_output --partial "npm token"
}

@test "secret inventory warns about ~/.pypirc with password" {
    source_functions

    printf '[pypi]\nusername = user\npassword = secret123\n' > "${HOME}/.pypirc"

    run audit_secret_inventory
    assert_output --partial "PyPI password/token"
}

@test "secret inventory clean state reports OK, no WARN" {
    source_functions

    run audit_secret_inventory
    refute_output --partial "[WARN]"
    assert_output --partial "No plaintext dev credentials detected"
}

# ===========================================================================
# v0.2.0: SSH key hygiene
# ===========================================================================

@test "SSH key hygiene: ed25519 reported as OK" {
    source_functions

    ssh-keygen -t ed25519 -f "${HOME}/.ssh/test_ed25519" -N "" -q
    run audit_ssh_key_hygiene
    assert_output --partial "[OK]"
    assert_output --partial "ed25519"
}

@test "SSH key hygiene: RSA key reported as WARN" {
    source_functions

    ssh-keygen -t rsa -b 2048 -f "${HOME}/.ssh/test_rsa" -N "" -q
    run audit_ssh_key_hygiene
    assert_output --partial "[WARN]"
    assert_output --partial "RSA"
    assert_output --partial "migrating to ed25519"
}

@test "SSH key hygiene: no keys produces info message" {
    source_functions

    # Remove the default keys created in setup (there are none)
    rm -f "${HOME}/.ssh/"*.pub

    run audit_ssh_key_hygiene
    assert_output --partial "No SSH public keys found"
}

@test "SSH key hygiene: picks up keys from IdentityFile in ssh config" {
    source_functions

    mkdir -p "${HOME}/.ssh/custom"
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/custom/my_key" -N "" -q
    printf 'IdentityFile ~/.ssh/custom/my_key\n' > "${HOME}/.ssh/config"

    run audit_ssh_key_hygiene
    assert_output --partial "[OK]"
    assert_output --partial "my_key"
}

# ===========================================================================
# v0.5.0: Identity guard (useConfigOnly)
# ===========================================================================

@test "audit warns when useConfigOnly=true but identity missing" {
    git config --global --unset user.name
    git config --global --unset user.email

    source_functions
    run audit_git_config
    assert_output --partial "user.name/user.email not set"
}

@test "audit does not warn about identity when name and email set" {
    source_functions
    run audit_git_config
    refute_output --partial "user.name/user.email not set"
}

@test "-y mode applies useConfigOnly when identity exists" {
    source_functions
    AUTO_YES=true
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"

    run apply_git_config
    assert_success

    [ "$(git config --global user.useConfigOnly)" = "true" ]
}

@test "-y mode skips useConfigOnly when user.name missing" {
    git config --global --unset user.name

    source_functions
    AUTO_YES=true
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"

    run apply_git_config
    assert_success
    assert_output --partial "Skipping user.useConfigOnly"

    local result
    result="$(git config --global --get user.useConfigOnly 2>/dev/null || true)"
    [ -z "$result" ]
}

@test "-y mode skips useConfigOnly when user.email missing" {
    git config --global --unset user.email

    source_functions
    AUTO_YES=true
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"

    run apply_git_config
    assert_success
    assert_output --partial "Skipping user.useConfigOnly"

    local result
    result="$(git config --global --get user.useConfigOnly 2>/dev/null || true)"
    [ -z "$result" ]
}

# ===========================================================================
# v0.5.0: pull.rebase unset during apply
# ===========================================================================

@test "-y mode unsets pull.rebase when set" {
    git config --global pull.rebase true

    source_functions
    AUTO_YES=true
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"

    run apply_git_config
    assert_success
    assert_output --partial "Unset pull.rebase"

    local result
    result="$(git config --global --get pull.rebase 2>/dev/null || true)"
    [ -z "$result" ]
}

@test "-y mode does not unset pull.rebase when not set" {
    source_functions
    AUTO_YES=true
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"

    run apply_git_config
    assert_success
    refute_output --partial "Unset pull.rebase"
}

# ===========================================================================
# v0.5.0: SSH directives in Host * block
# ===========================================================================

@test "apply places new SSH directive in Host * block when blocks exist" {
    cat > "${TEST_HOME}/.ssh/config" <<'SSHEOF'
Host github.com
    IdentityFile ~/.ssh/github_key
SSHEOF

    source_functions
    apply_single_ssh_directive "StrictHostKeyChecking" "accept-new"

    # Should have created a Host * block
    grep -q "^Host \*$" "${TEST_HOME}/.ssh/config"
    grep -q "StrictHostKeyChecking accept-new" "${TEST_HOME}/.ssh/config"
}

@test "apply adds global directive without shadowing host-specific blocks" {
    cat > "${TEST_HOME}/.ssh/config" <<'SSHEOF'
Host *
    HashKnownHosts yes

Host github.com
    IdentityFile ~/.ssh/github_key
SSHEOF

    source_functions
    apply_single_ssh_directive "IdentitiesOnly" "yes"

    grep -q "IdentitiesOnly yes" "${TEST_HOME}/.ssh/config"

    # ssh uses first-obtained-wins semantics: the new directive must land
    # AFTER the host-specific blocks (in a new Host * block at EOF) so it
    # cannot override per-host settings. Inserting into the top Host *
    # block would shadow every block below it.
    local directive_line github_line
    directive_line="$(grep -n 'IdentitiesOnly yes' "${TEST_HOME}/.ssh/config" | cut -d: -f1)"
    github_line="$(grep -n '^Host github.com$' "${TEST_HOME}/.ssh/config" | cut -d: -f1)"
    [ "$directive_line" -gt "$github_line" ]

    # The directive is recognized as the global value
    [ "$(get_ssh_directive_value IdentitiesOnly)" = "yes" ]
}

@test "apply replaces directive in global scope, not in host blocks" {
    cat > "${TEST_HOME}/.ssh/config" <<'SSHEOF'
Host legacy.example.com
    StrictHostKeyChecking yes

Host *
    StrictHostKeyChecking ask
SSHEOF

    source_functions
    apply_single_ssh_directive "StrictHostKeyChecking" "accept-new"

    # The host-specific value must be untouched
    grep -q "StrictHostKeyChecking yes" "${TEST_HOME}/.ssh/config"
    # The global (Host *) value must be replaced
    grep -q "StrictHostKeyChecking accept-new" "${TEST_HOME}/.ssh/config"
    ! grep -q "StrictHostKeyChecking ask" "${TEST_HOME}/.ssh/config"
}

@test "audit treats host-specific directive as not set globally" {
    cat > "${TEST_HOME}/.ssh/config" <<'SSHEOF'
Host github.com
    IdentitiesOnly yes
SSHEOF

    source_functions
    [ -z "$(get_ssh_directive_value IdentitiesOnly)" ]
}

@test "apply appends bare when no Host/Match blocks exist" {
    : > "${TEST_HOME}/.ssh/config"

    source_functions
    apply_single_ssh_directive "HashKnownHosts" "yes"

    grep -q "HashKnownHosts yes" "${TEST_HOME}/.ssh/config"
    # No Host * block should be created for a simple file
    ! grep -q "^Host" "${TEST_HOME}/.ssh/config"
}

# ===========================================================================
# v0.5.0: SSH config backup
# ===========================================================================

@test "apply_ssh_config creates backup of existing SSH config" {
    printf 'StrictHostKeyChecking ask\n' > "${TEST_HOME}/.ssh/config"

    source_functions
    AUTO_YES=true

    run apply_ssh_config
    assert_success
    assert_output --partial "SSH config backed up"

    # Verify backup file exists
    local backup_count
    backup_count="$(find "${TEST_HOME}/.ssh" -name 'config.pre-harden-*' | wc -l | tr -d ' ')"
    [ "$backup_count" -eq 1 ]

    # Verify backup contains original content
    local backup_file
    backup_file="$(find "${TEST_HOME}/.ssh" -name 'config.pre-harden-*' -print -quit)"
    grep -q "StrictHostKeyChecking ask" "$backup_file"
}

@test "apply_ssh_config does not create backup for new SSH config" {
    rm -f "${TEST_HOME}/.ssh/config"

    source_functions
    AUTO_YES=true

    run apply_ssh_config
    assert_success
    refute_output --partial "SSH config backed up"
}

# ===========================================================================
# v0.5.0: Dedicated signing key names
# ===========================================================================

@test "detect_existing_keys finds dedicated signing key" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519_signing" -N "" -q

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = true ]
    [ "$SIGNING_PUB_PATH" = "${TEST_HOME}/.ssh/id_ed25519_signing.pub" ]
}

@test "detect_existing_keys falls back to general key when no signing key" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = true ]
    [ "$SIGNING_PUB_PATH" = "${TEST_HOME}/.ssh/id_ed25519.pub" ]
}

@test "-y mode enables signing with dedicated signing key" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519_signing" -N "" -q

    source_functions
    AUTO_YES=true

    run apply_signing_config
    assert_success

    [ "$(git config --global commit.gpgsign)" = "true" ]
    local sigkey
    sigkey="$(git config --global user.signingkey)"
    [[ "$sigkey" = *"id_ed25519_signing.pub"* ]]
}

# ===========================================================================
# v0.5.0: core.hooksPath separate prompt
# ===========================================================================

@test "-y mode applies core.hooksPath separately from filesystem group" {
    source_functions
    AUTO_YES=true
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"

    run apply_git_config
    assert_success

    [ "$(git config --global core.hooksPath)" = "~/.config/git/hooks" ]
}

@test "-y mode skips core.hooksPath when already set" {
    git config --global core.hooksPath "~/.config/git/hooks"

    source_functions
    AUTO_YES=true
    PLATFORM="macos"
    DETECTED_CRED_HELPER="osxkeychain"

    run apply_git_config
    assert_success
    refute_output --partial "Global Hooks Path"
}

# ===========================================================================
# v0.5.0: reset-signing cleans configured key path
# ===========================================================================

@test "reset-signing cleans actual configured key path" {
    # Create a custom-named key
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/my_org_key" -N "" -q
    git config --global user.signingkey "${TEST_HOME}/.ssh/my_org_key.pub"
    git config --global commit.gpgsign true

    source_functions
    AUTO_YES=true

    run reset_signing
    assert_success

    # git config entries should be removed
    local sigkey
    sigkey="$(git config --global --get user.signingkey 2>/dev/null || true)"
    [ -z "$sigkey" ]

    # Not a dedicated *_signing key: it may double as an auth key, so the
    # files must be mentioned but left untouched
    assert_output --partial "my_org_key"
    [ -f "${TEST_HOME}/.ssh/my_org_key" ]
    [ -f "${TEST_HOME}/.ssh/my_org_key.pub" ]
}

@test "reset-signing includes dedicated signing key names" {
    # Create dedicated signing keys
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519_signing" -N "" -q

    source_functions
    AUTO_YES=true

    run reset_signing
    assert_success
    assert_output --partial "id_ed25519_signing"
}

# ===========================================================================
# v0.6.0: reset-signing never touches general-purpose keys
# ===========================================================================

@test "reset-signing never lists general-purpose keys for deletion" {
    # id_ed25519 is the user's likely SSH AUTH key — must never be a
    # deletion candidate even though detect_existing_keys can select it
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q

    source_functions
    AUTO_YES=true

    run reset_signing
    assert_success
    refute_output --partial "Signing key files found"
    [ -f "${TEST_HOME}/.ssh/id_ed25519" ]
    [ -f "${TEST_HOME}/.ssh/id_ed25519.pub" ]
}

@test "reset-signing -y never deletes dedicated signing key files" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519_signing" -N "" -q
    git config --global user.signingkey "${TEST_HOME}/.ssh/id_ed25519_signing.pub"

    source_functions
    AUTO_YES=true

    run reset_signing
    assert_success
    assert_output --partial "left in place"
    [ -f "${TEST_HOME}/.ssh/id_ed25519_signing" ]
    [ -f "${TEST_HOME}/.ssh/id_ed25519_signing.pub" ]
}

# ===========================================================================
# v0.6.0: signing key must be a public key
# ===========================================================================

@test "detect_existing_keys recovers when signingkey points at private key" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519_signing" -N "" -q
    git config --global user.signingkey "${TEST_HOME}/.ssh/id_ed25519_signing"

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = "true" ]
    [ "$SIGNING_PUB_PATH" = "${TEST_HOME}/.ssh/id_ed25519_signing.pub" ]
}

@test "setup_allowed_signers refuses private key material" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519_signing" -N "" -q

    source_functions
    SIGNING_PUB_PATH="${TEST_HOME}/.ssh/id_ed25519_signing"  # private key!

    run setup_allowed_signers
    assert_output --partial "refusing"
    [ ! -f "${TEST_HOME}/.config/git/allowed_signers" ]
}

# ===========================================================================
# v0.6.0: dispatch stubs keep repo-local hooks working
# ===========================================================================

@test "apply_dispatch_hooks installs stubs when hooksPath is ours" {
    git config --global core.hooksPath "~/.config/git/hooks"

    source_functions
    AUTO_YES=true

    run apply_dispatch_hooks
    assert_success
    [ -x "${TEST_HOME}/.config/git/hooks/pre-push" ]
    [ -x "${TEST_HOME}/.config/git/hooks/commit-msg" ]
    [ -x "${TEST_HOME}/.config/git/hooks/post-checkout" ]
}

@test "apply_dispatch_hooks is a no-op when hooksPath is not set" {
    source_functions
    AUTO_YES=true

    run apply_dispatch_hooks
    assert_success
    [ ! -f "${TEST_HOME}/.config/git/hooks/pre-push" ]
}

@test "global pre-commit hook dispatches to repo-local hook" {
    source_functions
    write_precommit_hook "${TEST_HOME}/.config/git/hooks/pre-commit"

    mkdir -p "${TEST_HOME}/repo"
    cd "${TEST_HOME}/repo"
    git init -q
    cat > .git/hooks/pre-commit <<'LOCALEOF'
#!/usr/bin/env bash
touch .local-hook-ran
LOCALEOF
    chmod +x .git/hooks/pre-commit

    run env SKIP_GITLEAKS=1 "${TEST_HOME}/.config/git/hooks/pre-commit"
    assert_success
    [ -f .local-hook-ran ]
}

@test "global pre-commit hook warns when gitleaks missing" {
    source_functions
    write_precommit_hook "${TEST_HOME}/.config/git/hooks/pre-commit"

    mkdir -p "${TEST_HOME}/repo"
    cd "${TEST_HOME}/repo"
    git init -q

    # PATH without gitleaks (keep git/bash/coreutils)
    run env PATH="/usr/bin:/bin" "${TEST_HOME}/.config/git/hooks/pre-commit"
    assert_success
    assert_output --partial "secret scan SKIPPED"
}

# ===========================================================================
# v0.6.0: audit tiers
# ===========================================================================

@test "audit exits 0 when only preference/hygiene issues remain" {
    # Apply every security-tier setting, leave init.defaultBranch and
    # log.showSignature (preference) and reflog/prune (hygiene) unset
    git config --global transfer.fsckObjects true
    git config --global fetch.fsckObjects true
    git config --global receive.fsckObjects true
    git config --global transfer.bundleURI false
    git config --global protocol.version 2
    git config --global protocol.allow never
    git config --global protocol.https.allow always
    git config --global protocol.ssh.allow always
    git config --global protocol.file.allow user
    git config --global protocol.git.allow never
    git config --global protocol.ext.allow never
    git config --global core.protectNTFS true
    git config --global core.protectHFS true
    git config --global core.fsmonitor false
    git config --global core.symlinks false
    git config --global core.hooksPath "~/.config/git/hooks"
    git config --global safe.bareRepository explicit
    git config --global submodule.recurse false
    git config --global pull.ff only
    git config --global merge.ff only
    git config --global 'url.https://.insteadOf' 'http://'
    git config --global credential.helper osxkeychain
    git config --global gpg.format ssh
    git config --global gpg.ssh.allowedSignersFile "~/.config/git/allowed_signers"
    git config --global commit.gpgsign true
    git config --global tag.gpgsign true
    git config --global tag.forceSignAnnotated true
    # Passphrase-protected so the on-disk private-key audit raises no
    # security-tier finding for an unencrypted key.
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519_signing" -N "harden-test-pass" -q
    git config --global user.signingkey "${TEST_HOME}/.ssh/id_ed25519_signing.pub"

    # Hooks (with dispatch stubs), gitignore, SSH config
    source_functions
    write_precommit_hook "${TEST_HOME}/.config/git/hooks/pre-commit"
    AUTO_YES=true
    apply_dispatch_hooks
    printf '.env\n*.pem\n*.key\n' > "${TEST_HOME}/.config/git/ignore"
    git config --global core.excludesFile "~/.config/git/ignore"
    cat > "${TEST_HOME}/.ssh/config" <<SSHEOF
StrictHostKeyChecking accept-new
IdentitiesOnly yes
PubkeyAcceptedAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com
SSHEOF

    run bash "$SCRIPT" --audit
    assert_success
    assert_output --partial "security: 0"
}

@test "audit exits 2 on security-tier issues" {
    git config --global protocol.ext.allow always

    run bash "$SCRIPT" --audit
    [ "$status" -eq 2 ]
}

@test "audit treats unset http.sslVerify as OK (git default)" {
    run bash "$SCRIPT" --audit
    assert_output --partial "http.sslVerify unset (git default: true"
}

@test "audit flags http.sslVerify=false as security issue" {
    git config --global http.sslVerify false

    run bash "$SCRIPT" --audit
    assert_output --partial "MITM risk"
}

# ===========================================================================
# v0.8.0: Version bump
# ===========================================================================

@test "--version reports 0.8.0" {
    run bash "$SCRIPT" --version
    assert_output --partial "0.8.0"
}

# ===========================================================================
# v0.7 Phase 1: Agent detection & audit
# ===========================================================================

@test "list_ssh_agent_sockets emits SSH_AUTH_SOCK as generic when no remote session" {
    source_functions
    # A plain path is fine; SSH_AUTH_SOCK is emitted regardless of socket-ness.
    export SSH_AUTH_SOCK="${TEST_HOME}/agent.sock"
    unset SSH_CONNECTION SSH_TTY

    run list_ssh_agent_sockets
    assert_output --partial "ssh-auth-sock	${TEST_HOME}/agent.sock"
    refute_output --partial "forwarded"
}

@test "list_ssh_agent_sockets labels a forwarded agent when SSH_CONNECTION set" {
    source_functions
    export SSH_AUTH_SOCK="${TEST_HOME}/agent.sock"
    export SSH_CONNECTION="10.0.0.1 5555 10.0.0.2 22"

    run list_ssh_agent_sockets
    assert_output --partial "forwarded	${TEST_HOME}/agent.sock"
    refute_output --partial "ssh-auth-sock"
}

@test "list_ssh_agent_sockets detects 1Password socket (Linux path)" {
    source_functions
    unset SSH_AUTH_SOCK
    mkdir -p "${TEST_HOME}/.1password"
    # Create a real unix socket via a throwaway agent so [[ -S ]] is true.
    start_test_agent
    # Point the 1Password path at the live agent socket.
    ln -s "$SSH_AUTH_SOCK" "${TEST_HOME}/.1password/agent.sock"
    unset SSH_AUTH_SOCK

    run list_ssh_agent_sockets
    assert_output --partial "1password	${TEST_HOME}/.1password/agent.sock"
}

@test "list_ssh_agent_sockets detects Bitwarden default socket" {
    source_functions
    unset SSH_AUTH_SOCK
    start_test_agent
    ln -s "$SSH_AUTH_SOCK" "${TEST_HOME}/.bitwarden-ssh-agent.sock"
    unset SSH_AUTH_SOCK

    run list_ssh_agent_sockets
    assert_output --partial "bitwarden	${TEST_HOME}/.bitwarden-ssh-agent.sock"
}

@test "list_ssh_agent_sockets detects gpg-agent via gpgconf stub" {
    source_functions
    unset SSH_AUTH_SOCK
    start_test_agent
    local gpgsock="${TEST_HOME}/gpg.ssh.sock"
    ln -s "$SSH_AUTH_SOCK" "$gpgsock"
    # Stub gpgconf earlier on PATH to report our socket.
    mkdir -p "${TEST_HOME}/bin"
    cat > "${TEST_HOME}/bin/gpgconf" <<GPGEOF
#!/usr/bin/env bash
printf '%s\n' "$gpgsock"
GPGEOF
    chmod +x "${TEST_HOME}/bin/gpgconf"
    PATH="${TEST_HOME}/bin:$PATH"
    unset SSH_AUTH_SOCK

    run list_ssh_agent_sockets
    assert_output --partial "gpg-agent	${gpgsock}"
}

@test "list_ssh_agent_sockets dedupes when SSH_AUTH_SOCK equals a vault socket" {
    source_functions
    start_test_agent
    ln -s "$SSH_AUTH_SOCK" "${TEST_HOME}/.bitwarden-ssh-agent.sock"
    # SSH_AUTH_SOCK already points at the same live socket via the agent.
    # Bitwarden symlink resolves elsewhere, so dedup is by the literal path:
    # set SSH_AUTH_SOCK to the bitwarden path to force a collision.
    export SSH_AUTH_SOCK="${TEST_HOME}/.bitwarden-ssh-agent.sock"

    run list_ssh_agent_sockets
    # Path should appear exactly once (as the generic SSH_AUTH_SOCK entry).
    local n
    n="$(printf '%s\n' "$output" | grep -c "${TEST_HOME}/.bitwarden-ssh-agent.sock")"
    [ "$n" -eq 1 ]
}

@test "agent_list_keys lists keys from a live agent and is read-only" {
    source_functions
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    # Prove the no-on-disk path: delete the private key file.
    rm -f "${TEST_HOME}/k1"

    run agent_list_keys "$SSH_AUTH_SOCK"
    assert_output --partial "ssh-ed25519"
    # Agent still holds exactly one key — agent_list_keys did not mutate it.
    run ssh-add -l
    assert_success
}

@test "audit_ssh_agents reports reachable agent with key count" {
    source_functions
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1"

    run audit_ssh_agents
    assert_output --partial "[OK]"
    assert_output --partial "reachable"
    assert_output --partial "1 key(s)"
}

@test "audit_ssh_agents reports unreachable socket" {
    source_functions
    # Dead socket path: file exists but nothing is listening.
    export SSH_AUTH_SOCK="${TEST_HOME}/dead.sock"
    : > "${TEST_HOME}/dead.sock"

    run audit_ssh_agents
    assert_output --partial "unreachable"
}

@test "audit_ssh_agents reports no agents when none present" {
    source_functions
    unset SSH_AUTH_SOCK

    run audit_ssh_agents
    assert_output --partial "No SSH agents detected"
}

@test "audit_ssh_agents reports reachable-but-empty agent as 0 keys" {
    source_functions
    # Live agent, no identities loaded: ssh-add -L prints the sentinel and
    # exits 1. Must be reported as reachable with 0 keys, not 1 phantom key.
    start_test_agent

    run audit_ssh_agents
    assert_output --partial "0 keys loaded"
    refute_output --partial "1 key(s)"
}

@test "full --audit does not abort on a dead SSH_AUTH_SOCK" {
    # 'run <function>' masks errexit, so the regression only shows when the
    # whole script runs. ssh-add exits 2 on an unreachable socket; under
    # errexit a bare probe would abort the audit mid-run. The script must
    # complete and still emit its closing summary.
    export SSH_AUTH_SOCK="${TEST_HOME}/dead.sock"
    : > "${TEST_HOME}/dead.sock"

    run bash "$SCRIPT" --audit
    assert_output --partial "unreachable"
    assert_output --partial "Audit Summary"
}

@test "audit_ssh_key_hygiene emits no phantom key for an empty agent" {
    source_functions
    rm -f "${HOME}/.ssh/"*.pub
    # Reachable-but-empty agent must not be parsed as a key (the sentinel
    # 'The agent has no identities.' must never surface as an (agent:) entry
    # or an 'unknown type' line).
    start_test_agent

    run audit_ssh_key_hygiene
    refute_output --partial "(agent:"
    refute_output --partial "unknown type"
    assert_output --partial "No SSH public keys found"
}

@test "audit_ssh_key_hygiene merges and labels agent keys" {
    source_functions
    rm -f "${HOME}/.ssh/"*.pub
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    run audit_ssh_key_hygiene
    assert_output --partial "(agent: ssh-auth-sock)"
    refute_output --partial "No SSH public keys found"
}

@test "audit_ssh_key_hygiene dedupes a key present on disk and in the agent" {
    source_functions
    rm -f "${HOME}/.ssh/"*.pub
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "" -q
    start_test_agent
    ssh-add "${HOME}/.ssh/id_ed25519" >/dev/null 2>&1

    run audit_ssh_key_hygiene
    # Same blob: reported once from disk, not again as an agent entry.
    assert_output --partial "id_ed25519.pub"
    refute_output --partial "(agent:"
}

@test "audit_ssh_key_hygiene applies weak-algo checks to agent keys" {
    source_functions
    rm -f "${HOME}/.ssh/"*.pub
    start_test_agent
    ssh-keygen -t rsa -b 1024 -f "${TEST_HOME}/weak" -N "" -q 2>/dev/null \
        || ssh-keygen -t rsa -b 2048 -f "${TEST_HOME}/weak" -N "" -q
    ssh-add "${TEST_HOME}/weak" >/dev/null 2>&1
    rm -f "${TEST_HOME}/weak" "${TEST_HOME}/weak.pub"

    run audit_ssh_key_hygiene
    assert_output --partial "(agent: ssh-auth-sock)"
    assert_output --partial "RSA"
    assert_output --partial "[WARN]"
}

@test "audit_ssh_key_hygiene says no keys only when disk and agents empty" {
    source_functions
    rm -f "${HOME}/.ssh/"*.pub
    unset SSH_AUTH_SOCK

    run audit_ssh_key_hygiene
    assert_output --partial "No SSH public keys found"
}

@test "is_private_key_file detects by header, not filename" {
    source_functions
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/oddname" -N "" -q
    # Private key with a non-standard name (no .pub-less convention reliance).
    run is_private_key_file "${TEST_HOME}/.ssh/oddname"
    assert_success
    # A public key file must NOT be classified as private.
    run is_private_key_file "${TEST_HOME}/.ssh/oddname.pub"
    assert_failure
}

@test "private_key_is_unencrypted true for plaintext key, false for passphrase key" {
    source_functions
    ssh-keygen -t ed25519 -f "${TEST_HOME}/plain" -N "" -q
    ssh-keygen -t ed25519 -f "${TEST_HOME}/enc" -N "secret-pass" -q

    run private_key_is_unencrypted "${TEST_HOME}/plain"
    assert_success
    run private_key_is_unencrypted "${TEST_HOME}/enc"
    assert_failure
}

@test "audit_ssh_private_keys WARNs (security) on unencrypted key" {
    source_functions
    unset SSH_AUTH_SOCK
    rm -f "${HOME}/.ssh/"*
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "" -q
    AUDIT_WARN=0; TIER_SECURITY_ISSUES=0

    run audit_ssh_private_keys
    assert_output --partial "[WARN]"
    assert_output --partial "Unencrypted private key on disk"
}

@test "audit_ssh_private_keys does not flag an encrypted key red" {
    source_functions
    unset SSH_AUTH_SOCK
    rm -f "${HOME}/.ssh/"*
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "secret-pass" -q

    run audit_ssh_private_keys
    refute_output --partial "[WARN]"
    refute_output --partial "[MISS]"
    assert_output --partial "encrypted"
}

@test "audit_ssh_private_keys INFOs an encrypted key also held by an agent" {
    source_functions
    rm -f "${HOME}/.ssh/"*
    # Encrypted key on disk.
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "secret-pass" -q
    # A decrypted copy (same key material, empty passphrase) loaded into the
    # agent — its public blob matches the on-disk encrypted key's blob.
    cp "${HOME}/.ssh/id_ed25519" "${TEST_HOME}/copy"
    chmod 600 "${TEST_HOME}/copy"
    ssh-keygen -p -P "secret-pass" -N "" -f "${TEST_HOME}/copy" -q
    start_test_agent
    ssh-add "${TEST_HOME}/copy" >/dev/null 2>&1
    rm -f "${TEST_HOME}/copy" "${TEST_HOME}/copy.pub"

    run audit_ssh_private_keys
    assert_output --partial "candidate for cleanup"
}

@test "audit_ssh_private_keys reports none when ~/.ssh has no private keys" {
    source_functions
    unset SSH_AUTH_SOCK
    rm -f "${HOME}/.ssh/"*

    run audit_ssh_private_keys
    assert_output --partial "No private keys found on disk"
}

@test "ForwardAgent audit: OK when unset globally" {
    source_functions
    cat > "${HOME}/.ssh/config" <<'SSHEOF'
StrictHostKeyChecking accept-new
SSHEOF

    run audit_ssh_config
    assert_output --partial "ForwardAgent unset globally"
}

@test "ForwardAgent audit: OK when no globally" {
    source_functions
    cat > "${HOME}/.ssh/config" <<'SSHEOF'
ForwardAgent no
SSHEOF

    run audit_ssh_config
    assert_output --partial "ForwardAgent = no"
    refute_output --partial "any root user"
}

@test "ForwardAgent audit: WARN (security) when yes globally" {
    source_functions
    cat > "${HOME}/.ssh/config" <<'SSHEOF'
ForwardAgent yes
SSHEOF
    TIER_SECURITY_ISSUES=0

    run audit_ssh_config
    assert_output --partial "[WARN]"
    assert_output --partial "ForwardAgent = yes"
    assert_output --partial "any root user"
}

@test "ForwardAgent audit: yes in host-specific block does not trigger global WARN" {
    source_functions
    cat > "${HOME}/.ssh/config" <<'SSHEOF'
Host bastion
    ForwardAgent yes
SSHEOF

    run audit_ssh_config
    # Host-scoped ForwardAgent yes is not a global default → no "any root user".
    refute_output --partial "any root user"
}

@test "agent end-to-end: key with no private file on disk is audited" {
    source_functions
    rm -f "${HOME}/.ssh/"*
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/e2e" -N "" -q
    ssh-add "${TEST_HOME}/e2e" >/dev/null 2>&1
    # Remove the on-disk private AND public material entirely.
    rm -f "${TEST_HOME}/e2e" "${TEST_HOME}/e2e.pub"

    # Hygiene sees the agent key; private-key audit finds nothing on disk.
    run audit_ssh_key_hygiene
    assert_output --partial "(agent: ssh-auth-sock)"

    run audit_ssh_private_keys
    assert_output --partial "No private keys found on disk"
}

# ===========================================================================
# v0.7-P2: Agent-backed signing
# ===========================================================================

@test "list_modern_agent_keys lists a modern agent key as a full pubkey line" {
    source_functions
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -C "me@example.com" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    run list_modern_agent_keys
    assert_success
    assert_output --partial "ssh-ed25519 "
    assert_output --partial "me@example.com"
}

@test "list_modern_agent_keys filters out weak (RSA) agent keys" {
    source_functions
    start_test_agent
    ssh-keygen -t rsa -b 2048 -f "${TEST_HOME}/rsa" -N "" -q
    ssh-add "${TEST_HOME}/rsa" >/dev/null 2>&1
    rm -f "${TEST_HOME}/rsa" "${TEST_HOME}/rsa.pub"

    run list_modern_agent_keys
    assert_success
    refute_output --partial "ssh-rsa"
}

@test "list_modern_agent_keys dedupes the same key across sockets" {
    source_functions
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"
    # Expose the same live agent socket a second time via the 1Password path.
    mkdir -p "${TEST_HOME}/.1password"
    ln -s "$SSH_AUTH_SOCK" "${TEST_HOME}/.1password/agent.sock"

    run list_modern_agent_keys
    assert_success
    local n
    n="$(printf '%s\n' "$output" | grep -c "ssh-ed25519")"
    [ "$n" -eq 1 ]
}

@test "setup_allowed_signers accepts public key MATERIAL as an argument" {
    source_functions
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    local pub
    pub="$(cat "${TEST_HOME}/k1.pub")"
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"
    SIGNING_PUB_PATH=""

    run setup_allowed_signers "$pub"
    assert_success
    [ -f "${TEST_HOME}/.config/git/allowed_signers" ]
    grep -q "test@example.com" "${TEST_HOME}/.config/git/allowed_signers"
    grep -q "ssh-ed25519" "${TEST_HOME}/.config/git/allowed_signers"
}

@test "setup_allowed_signers refuses private key MATERIAL passed as argument" {
    source_functions
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    local priv
    priv="$(cat "${TEST_HOME}/k1")"

    run setup_allowed_signers "$priv"
    assert_output --partial "not an SSH public key"
    [ ! -f "${TEST_HOME}/.config/git/allowed_signers" ]
}

@test "enable_signing_agent_key sets key:: value and writes allowed_signers" {
    source_functions
    AUTO_YES=true   # skip the interactive smoke test
    unset SSH_AUTH_SOCK SSH_AGENT_PID   # deterministic: don't probe a real agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    local pub
    pub="$(cat "${TEST_HOME}/k1.pub")"
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    run enable_signing_agent_key "$pub"
    assert_success

    local configured
    configured="$(git config --global --get user.signingkey)"
    [[ "$configured" == key::ssh-ed25519* ]]
    [ "$(git config --global --get commit.gpgsign)" = "true" ]
    grep -q "ssh-ed25519" "${TEST_HOME}/.config/git/allowed_signers"
}

@test "audit_signing accepts key:: value present in allowed_signers" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    local pub blob
    pub="$(cat "${TEST_HOME}/k1.pub")"
    blob="$(printf '%s' "$pub" | awk '{print $2}')"
    git config --global user.signingkey "key::${pub}"
    git config --global gpg.format ssh
    printf 'test@example.com ssh-ed25519 %s\n' "$blob" > "${TEST_HOME}/.config/git/allowed_signers"
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    source_functions
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_signing
    assert_output --partial "[OK]"
    assert_output --partial "agent key"
    assert_output --partial "present in allowed_signers"
}

@test "audit_signing warns on key:: value missing from allowed_signers" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    local pub
    pub="$(cat "${TEST_HOME}/k1.pub")"
    git config --global user.signingkey "key::${pub}"
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    source_functions
    AUDIT_OK=0; AUDIT_WARN=0; AUDIT_MISS=0

    run audit_signing
    assert_output --partial "[WARN]"
    assert_output --partial "not in allowed_signers"
}

@test "-y mode auto-adopts a single modern agent key for signing" {
    source_functions
    AUTO_YES=true
    rm -f "${HOME}/.ssh/"*
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    run apply_signing_config
    assert_success

    local configured
    configured="$(git config --global --get user.signingkey)"
    [[ "$configured" == key::ssh-ed25519* ]]
}

@test "-y mode stays passive when multiple agent keys are loaded" {
    source_functions
    AUTO_YES=true
    rm -f "${HOME}/.ssh/"*
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k2" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    ssh-add "${TEST_HOME}/k2" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub" "${TEST_HOME}/k2" "${TEST_HOME}/k2.pub"

    run apply_signing_config
    assert_success
    assert_output --partial "No SSH signing key found"
    [ -z "$(git config --global --get user.signingkey || true)" ]
}

@test "agent end-to-end: verify_signing_setup signs via -U with no private file" {
    source_functions
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -C "test@example.com" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    local pub blob
    pub="$(cat "${TEST_HOME}/k1.pub")"
    blob="$(printf '%s' "$pub" | awk '{print $2}')"
    # Prove the zero-plaintext path: remove both private and public files.
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    # allowed_signers carries the same blob under the recorded principal.
    printf 'test@example.com ssh-ed25519 %s\n' "$blob" > "${TEST_HOME}/.config/git/allowed_signers"
    SIGNING_PRINCIPAL="test@example.com"
    AUTO_YES=false
    # Auto-accept the "verify now?" prompt without a tty.
    prompt_yn() { return 0; }

    run verify_signing_setup "" "$pub"
    assert_success
    assert_output --partial "Signature round-trip verified"
}

# ===========================================================================
# v0.7-P3: SSH config integration (IdentitiesOnly guard, IdentityAgent,
# ForwardAgent default)
# ===========================================================================

@test "sanitize_stub_name keeps safe chars and collapses the rest" {
    source_functions
    run sanitize_stub_name 'me@example.com'
    assert_output 'me_example.com'

    run sanitize_stub_name '  weird // name!! '
    assert_output 'weird_name'
}

@test "agent_key_stub_name derives a name from the key comment" {
    source_functions
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -C "laptop@home" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    local key
    key="$(cat "${TEST_HOME}/k1.pub")"
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    run agent_key_stub_name "$key"
    assert_output 'laptop_home'
}

@test "agent_key_stub_name falls back to agent_<fp> when no comment" {
    source_functions
    # A bare key line with no comment field.
    local key
    key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    run agent_key_stub_name "$key"
    assert_output --partial "agent_"
}

@test "IdentitiesOnly guard: safe when a global IdentityFile already exists" {
    source_functions
    cat > "${HOME}/.ssh/config" <<'SSHEOF'
IdentityFile ~/.ssh/id_ed25519
SSHEOF
    run identities_only_guard
    assert_success
}

@test "IdentitiesOnly guard: safe when no agents hold keys" {
    source_functions
    unset SSH_AUTH_SOCK
    : > "${HOME}/.ssh/config"
    run identities_only_guard
    assert_success
}

@test "IdentitiesOnly guard: safe when an on-disk .pub stub matches an agent key" {
    source_functions
    : > "${HOME}/.ssh/config"
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    # Keep the .pub stub on disk, delete only the private half.
    cp "${TEST_HOME}/k1.pub" "${HOME}/.ssh/k1.pub"
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    run identities_only_guard
    assert_success
}

@test "IdentitiesOnly guard: agent-only with no stubs writes pub stubs + IdentityFile" {
    source_functions
    AUTO_YES=false
    : > "${HOME}/.ssh/config"
    rm -f "${HOME}/.ssh/"*.pub
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -C "vaultkey@host" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"
    # Accept the stub-writing prompt.
    prompt_yn() { return 0; }

    run identities_only_guard
    assert_success
    # A public-key stub now exists and an IdentityFile line points at it.
    [ -f "${HOME}/.ssh/vaultkey_host.pub" ]
    grep -q "IdentityFile ${HOME}/.ssh/vaultkey_host" "${HOME}/.ssh/config"
    # The stub holds ONLY public material.
    run head -1 "${HOME}/.ssh/vaultkey_host.pub"
    assert_output --partial "ssh-ed25519 "
    refute_output --partial "PRIVATE"
}

@test "IdentitiesOnly guard: TWO agent keys write a stub + IdentityFile PER key (no collapse)" {
    source_functions
    AUTO_YES=false
    : > "${HOME}/.ssh/config"
    rm -f "${HOME}/.ssh/"*.pub
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -C "vaultkey1@host" -N "" -q
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k2" -C "vaultkey2@host" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    ssh-add "${TEST_HOME}/k2" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub" "${TEST_HOME}/k2" "${TEST_HOME}/k2.pub"
    prompt_yn() { return 0; }

    run identities_only_guard
    assert_success
    # Both stubs written...
    [ -f "${HOME}/.ssh/vaultkey1_host.pub" ]
    [ -f "${HOME}/.ssh/vaultkey2_host.pub" ]
    # ...and TWO IdentityFile lines (the single-value replace bug collapsed
    # these into one, re-introducing the very lockout the guard prevents).
    run grep -cE '^[[:space:]]*IdentityFile ' "${HOME}/.ssh/config"
    assert_output "2"
}

@test "IdentitiesOnly guard: decline skips the directive (no lockout)" {
    source_functions
    AUTO_YES=false
    : > "${HOME}/.ssh/config"
    rm -f "${HOME}/.ssh/"*.pub
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"
    # Decline the stub-writing prompt.
    prompt_yn() { return 1; }

    run identities_only_guard
    assert_failure
    assert_output --partial "lock out"
    # No stub written, no IdentityFile added to the config.
    [ -z "$(ls "${HOME}/.ssh/"*.pub 2>/dev/null || true)" ]
    run grep -c "IdentityFile" "${HOME}/.ssh/config"
    assert_output "0"
}

@test "IdentitiesOnly guard: -y mode agent-only skips without prompting" {
    source_functions
    AUTO_YES=true
    : > "${HOME}/.ssh/config"
    rm -f "${HOME}/.ssh/"*.pub
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    run identities_only_guard
    assert_failure
    assert_output --partial "-y mode"
}

@test "apply_ssh_config: -y agent-only never writes IdentitiesOnly (no lockout)" {
    source_functions
    AUTO_YES=true
    : > "${HOME}/.ssh/config"
    rm -f "${HOME}/.ssh/"*.pub
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    run apply_ssh_config
    assert_success
    run grep -c "IdentitiesOnly yes" "${HOME}/.ssh/config"
    assert_output "0"
}

@test "apply_identity_agent_offer: offers IdentityAgent for a detected vault socket" {
    source_functions
    AUTO_YES=true
    : > "${HOME}/.ssh/config"
    start_test_agent
    ln -s "$SSH_AUTH_SOCK" "${TEST_HOME}/.bitwarden-ssh-agent.sock"
    # SSH_AUTH_SOCK must NOT already point at the vault socket.
    unset SSH_AUTH_SOCK

    run apply_identity_agent_offer
    assert_success
    grep -q "IdentityAgent ${TEST_HOME}/.bitwarden-ssh-agent.sock" "${HOME}/.ssh/config"
}

@test "apply_identity_agent_offer: never overwrites an existing IdentityAgent" {
    source_functions
    AUTO_YES=true
    cat > "${HOME}/.ssh/config" <<'SSHEOF'
IdentityAgent ~/.mine/agent.sock
SSHEOF
    start_test_agent
    ln -s "$SSH_AUTH_SOCK" "${TEST_HOME}/.bitwarden-ssh-agent.sock"
    unset SSH_AUTH_SOCK

    run apply_identity_agent_offer
    assert_success
    # The existing value is preserved; the vault socket is not appended.
    [ "$(get_ssh_directive_value IdentityAgent)" = "~/.mine/agent.sock" ]
    run grep -c "IdentityAgent" "${HOME}/.ssh/config"
    assert_output "1"
}

@test "apply_identity_agent_offer: no offer when SSH_AUTH_SOCK already points at the vault" {
    source_functions
    AUTO_YES=true
    : > "${HOME}/.ssh/config"
    start_test_agent
    ln -s "$SSH_AUTH_SOCK" "${TEST_HOME}/.bitwarden-ssh-agent.sock"
    export SSH_AUTH_SOCK="${TEST_HOME}/.bitwarden-ssh-agent.sock"

    run apply_identity_agent_offer
    assert_success
    refute_output --partial "IdentityAgent"
    [ -z "$(get_ssh_directive_value IdentityAgent)" ]
}

@test "apply_ssh_config: applies ForwardAgent no as a global default" {
    source_functions
    AUTO_YES=true
    unset SSH_AUTH_SOCK
    : > "${HOME}/.ssh/config"
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "" -q

    run apply_ssh_config
    assert_success
    [ "$(get_ssh_directive_value ForwardAgent)" = "no" ]
}

# ===========================================================================
# v0.7-P4: Migration assistant (interactive only, opt-in, never in -y)
# ===========================================================================

@test "--migrate combined with -y is rejected" {
    run bash "$SCRIPT" --migrate -y
    assert_failure
    assert_output --partial "interactive only"
}

@test "run_migration never deletes in -y mode" {
    source_functions
    AUTO_YES=true
    rm -f "${HOME}/.ssh/"*
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "" -q

    run run_migration
    assert_success
    assert_output --partial "never runs in -y"
    # The on-disk private key must remain untouched.
    [ -f "${HOME}/.ssh/id_ed25519" ]
    [ -f "${HOME}/.ssh/id_ed25519.pub" ]
}

@test "run_migration reports nothing to migrate when no private keys on disk" {
    source_functions
    AUTO_YES=false
    unset SSH_AUTH_SOCK
    rm -f "${HOME}/.ssh/"*

    run run_migration
    assert_success
    assert_output --partial "No on-disk private keys found"
}

@test "run_migration: deletion prompt defaults to No (key kept on empty answer)" {
    source_functions
    AUTO_YES=false
    rm -f "${HOME}/.ssh/"*
    # A key already represented in the agent (so the import-confirm step is
    # skipped and we go straight to the deletion offer).
    start_test_agent
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "" -q
    ssh-add "${HOME}/.ssh/id_ed25519" >/dev/null 2>&1

    # prompt_yn with default "n" returns 1 on an empty answer; emulate a user
    # pressing Enter at every prompt by honoring the supplied default.
    prompt_yn() {
        local default="${2:-y}"
        [ "$default" = "y" ]
    }

    run run_migration
    assert_success
    # Default-No means neither delete nor rename fired.
    assert_output --partial "Left ${HOME}/.ssh/id_ed25519 in place"
    [ -f "${HOME}/.ssh/id_ed25519" ]
    [ -f "${HOME}/.ssh/id_ed25519.pub" ]
}

@test "run_migration: confirmed deletion removes private key but keeps .pub stub" {
    source_functions
    AUTO_YES=false
    rm -f "${HOME}/.ssh/"*
    start_test_agent
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "" -q
    ssh-add "${HOME}/.ssh/id_ed25519" >/dev/null 2>&1

    # Accept the first deletion prompt.
    prompt_yn() { return 0; }

    run run_migration
    assert_success
    assert_output --partial "Deleted private key"
    # Private half gone, public stub kept for IdentitiesOnly.
    [ ! -f "${HOME}/.ssh/id_ed25519" ]
    [ -f "${HOME}/.ssh/id_ed25519.pub" ]
}

@test "run_migration: rename-to-.bak middle option keeps .pub stub" {
    source_functions
    AUTO_YES=false
    rm -f "${HOME}/.ssh/"*
    start_test_agent
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "" -q
    ssh-add "${HOME}/.ssh/id_ed25519" >/dev/null 2>&1

    # Decline delete (first prompt), accept rename (second prompt). The first
    # prompt_yn call in migration_offer_delete is the delete; the second is the
    # rename. Decline only the delete.
    prompt_yn() {
        case "$1" in
            "Delete the on-disk private key"*) return 1 ;;
            *) return 0 ;;
        esac
    }

    run run_migration
    assert_success
    assert_output --partial "Renamed private key"
    # Original private key path no longer holds the plaintext key.
    [ ! -f "${HOME}/.ssh/id_ed25519" ]
    # A .bak copy now exists, and the .pub stub is kept.
    ls "${HOME}/.ssh/id_ed25519.bak."* >/dev/null 2>&1
    [ -f "${HOME}/.ssh/id_ed25519.pub" ]
}

@test "run_migration: prints vault import instructions for a key not in the agent" {
    source_functions
    AUTO_YES=false
    rm -f "${HOME}/.ssh/"*
    # A live agent that does NOT hold this key, exposed via the 1Password path.
    start_test_agent
    mkdir -p "${HOME}/.1password"
    ln -s "$SSH_AUTH_SOCK" "${HOME}/.1password/agent.sock"
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "" -q
    # Do NOT load it into the agent.

    # Decline the "have you imported it?" prompt so no deletion is offered.
    prompt_yn() { return 1; }

    run run_migration
    assert_success
    assert_output --partial "1Password"
    # The 1Password path leads with the Watchtower bulk-import flow.
    assert_output --partial "Watchtower"
    assert_output --partial "Developer credentials on disk"
    # Key untouched because import was not confirmed.
    [ -f "${HOME}/.ssh/id_ed25519" ]
}

@test "run_migration: does not offer deletion until the agent holds the key" {
    source_functions
    AUTO_YES=false
    rm -f "${HOME}/.ssh/"*
    start_test_agent
    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -N "" -q
    # Key is NOT in the agent. User claims it was imported, but the probe
    # disagrees: deletion must not be offered.
    prompt_yn() {
        case "$1" in
            "Have you imported"*) return 0 ;;
            *) return 0 ;;
        esac
    }

    run run_migration
    assert_success
    assert_output --partial "does not yet hold"
    refute_output --partial "Deleted private key"
    [ -f "${HOME}/.ssh/id_ed25519" ]
}

@test "private_key_pub_blob derives blob from sibling .pub file" {
    source_functions
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    local expected
    expected="$(awk '{print $2}' "${TEST_HOME}/k1.pub")"

    run private_key_pub_blob "${TEST_HOME}/k1"
    assert_success
    assert_output "$expected"
}

@test "list_agent_pub_blobs lists the blob of a loaded agent key" {
    source_functions
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k1" -N "" -q
    local expected
    expected="$(awk '{print $2}' "${TEST_HOME}/k1.pub")"
    ssh-add "${TEST_HOME}/k1" >/dev/null 2>&1
    rm -f "${TEST_HOME}/k1" "${TEST_HOME}/k1.pub"

    run list_agent_pub_blobs
    assert_success
    assert_output --partial "$expected"
}
# ===========================================================================
# v0.8 Phase 1: Secret inventory — registry, tiers, read discipline
# ===========================================================================

# AC-1: detect a plaintext AWS credentials file (security tier, value hidden)
@test "AC-1: detects AWS static keys, names kind+path, hides value" {
    source_functions
    mkdir -p "${HOME}/.aws"
    printf '[default]\naws_access_key_id=AKIAEXAMPLE\naws_secret_access_key=SENTINEL_LEAK_CHECK\n' \
        > "${HOME}/.aws/credentials"

    run audit_secret_inventory
    assert_output --partial "AWS static keys"
    assert_output --partial "${HOME}/.aws/credentials"
    refute_output --partial "SENTINEL_LEAK_CHECK"
}

# AC-2: content-gated file with no secret is not flagged
@test "AC-2: npmrc with no _authToken is not flagged" {
    source_functions
    printf 'registry=https://registry.npmjs.org/\n//host/:always-auth=true\n' > "${HOME}/.npmrc"

    run audit_secret_inventory
    refute_output --partial "npm token"
}

# AC-3: no secret value ever appears in output, across many file kinds
@test "AC-3: sentinel value never appears in inventory output" {
    source_functions
    mkdir -p "${HOME}/.aws" "${HOME}/.config/gh" "${HOME}/.kube" "${HOME}/.m2"
    printf 'aws_secret_access_key=SENTINEL_LEAK_CHECK\n' > "${HOME}/.aws/credentials"
    printf '//r/:_authToken=SENTINEL_LEAK_CHECK\n' > "${HOME}/.npmrc"
    printf 'github.com:\n  oauth_token: SENTINEL_LEAK_CHECK\n' > "${HOME}/.config/gh/hosts.yml"
    printf 'users:\n- user:\n    token: SENTINEL_LEAK_CHECK\n' > "${HOME}/.kube/config"
    printf '<settings><servers><server><password>SENTINEL_LEAK_CHECK</password></server></servers></settings>\n' \
        > "${HOME}/.m2/settings.xml"

    run audit_secret_inventory
    assert_success
    refute_output --partial "SENTINEL_LEAK_CHECK"
}

# AC-15 (part 2): a 100KB single-line value still detected, never leaked
@test "AC-15: 100KB npm token value detected without leaking" {
    source_functions
    {
        printf '//registry.npmjs.org/:_authToken='
        head -c 102400 /dev/zero | tr '\0' 'X'
        printf '\n'
    } > "${HOME}/.npmrc"

    run audit_secret_inventory
    assert_output --partial "npm token"
    refute_output --partial "XXXXXXXXXX"
}

# AC-15 (part 1): static check — no content detection pattern uses a
# value-spanning construct (.+ .* {n,} or a capture group spanning the value).
# The pip URL-embedded pattern is the documented FR1.1 exception, but it too
# uses neither .+/.*/{ so the blanket no-value-spanning check holds for all.
@test "AC-15: detection regexes obey minimal-read discipline (static)" {
    # Collect every single-quoted ERE that is an argument to a
    # secret_report_content call, plus the SECRET_ASSIGN_ERE constant body.
    local patterns
    patterns="$(grep -E "secret_report_content|SECRET_ASSIGN_ERE=" "$SCRIPT" \
        | grep -oE "'[^']*'" || true)"
    [ -n "$patterns" ]

    # No content pattern may contain a value-spanning quantifier (.+ .* {n,}).
    run grep -E '\.\+|\.\*|\{[0-9]' <<<"$patterns"
    assert_failure

    # No call site pipes a matched line into sed/awk/cut.
    run grep -nE 'scan_quiet[^|]*\|[[:space:]]*(sed|awk|cut)' "$SCRIPT"
    assert_failure
}

# AC-3 wording / AC-11-adjacent: Docker auth uses "recoverable" wording, and
# credsStore suppresses the finding.
@test "secret inventory: docker auth flagged, credsStore suppresses it" {
    source_functions
    mkdir -p "${HOME}/.docker"
    printf '{"auths":{"reg":{"auth":"c2VjcmV0"}}}\n' > "${HOME}/.docker/config.json"
    run audit_secret_inventory
    assert_output --partial "Docker registry auth"
    assert_output --partial "recoverable by any local process"

    printf '{"auths":{"reg":{"auth":"c2VjcmV0"}},"credsStore":"desktop"}\n' \
        > "${HOME}/.docker/config.json"
    run audit_secret_inventory
    refute_output --partial "Docker registry auth"
}

# json-marker two-pass: service_account + private_key
@test "secret inventory: gcloud service-account JSON via json-marker" {
    source_functions
    mkdir -p "${HOME}/.config/gcloud/legacy_credentials/acct"
    printf '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----X"}\n' \
        > "${HOME}/.config/gcloud/legacy_credentials/acct/adc.json"
    run audit_secret_inventory
    assert_output --partial "GCP service-account key"

    # A JSON with the type marker but NO private_key must not match (2nd pass).
    printf '{"type":"service_account"}\n' \
        > "${HOME}/.config/gcloud/legacy_credentials/acct/adc.json"
    run audit_secret_inventory
    refute_output --partial "GCP service-account key"
}

# dir-nonempty: GPG private keys (info tier)
@test "secret inventory: GPG private-keys dir reported as INFO when non-empty" {
    source_functions
    mkdir -p "${HOME}/.gnupg/private-keys-v1.d"
    printf 'x' > "${HOME}/.gnupg/private-keys-v1.d/ABC.key"
    run audit_secret_inventory
    assert_output --partial "[INFO]"
    assert_output --partial "GPG private keys present"
}

@test "secret inventory: empty GPG private-keys dir not reported" {
    source_functions
    mkdir -p "${HOME}/.gnupg/private-keys-v1.d"
    run audit_secret_inventory
    refute_output --partial "GPG private keys present"
}

# AC-7: the inventory's security-tier counter reflects security findings only.
# (The full --audit exit also reflects the unrelated git-config audit, so this
# isolates the inventory's contribution via the per-tier counters.)
@test "AC-7: only-hygiene inventory findings add 0 to the security tier" {
    source_functions
    TIER_SECURITY_ISSUES=0
    mkdir -p "${HOME}/.gradle"
    printf 'signing.password=hunter2\n' > "${HOME}/.gradle/gradle.properties"

    audit_secret_inventory
    assert_equal "$TIER_SECURITY_ISSUES" 0
}

@test "AC-7: a ~/.pgpass (security) increments the security tier" {
    source_functions
    TIER_SECURITY_ISSUES=0
    printf 'localhost:5432:db:user:secret\n' > "${HOME}/.pgpass"

    audit_secret_inventory
    [ "$TIER_SECURITY_ISSUES" -gt 0 ]
}

# AC-18: under the script's own set -euo pipefail, every content-gated file
# present but with no secret marker must not abort the run. Run the REAL script
# (strict flags active) and assert it reaches the final "Audit Summary" header:
# if a routine scanner no-match (exit 1) aborted mid-run, that header would
# never print. The inventory must also contribute no plaintext finding.
@test "AC-18: content files present-but-empty never abort the run" {
    mkdir -p "${HOME}/.aws" "${HOME}/.docker" "${HOME}/.kube" "${HOME}/.gradle" \
             "${HOME}/.config/doctl" "${HOME}/.config/gh" "${HOME}/.config/glab-cli" \
             "${HOME}/.config/pip" "${HOME}/.config/NuGet" "${HOME}/.m2"
    # All present, none containing their marker.
    printf '[default]\nregion=us-east-1\n' > "${HOME}/.aws/credentials"
    printf '{"auths":{}}\n' > "${HOME}/.docker/config.json"
    printf 'apiVersion: v1\n' > "${HOME}/.kube/config"
    printf 'org.gradle.jvmargs=-Xmx2g\n' > "${HOME}/.gradle/gradle.properties"
    printf 'context: default\n' > "${HOME}/.config/doctl/config.yaml"
    printf 'github.com:\n  user: me\n' > "${HOME}/.config/gh/hosts.yml"
    printf 'gitlab.com:\n  user: me\n' > "${HOME}/.config/glab-cli/config.yml"
    printf '[global]\nindex-url=https://pypi.org/simple\n' > "${HOME}/.config/pip/pip.conf"
    printf '<configuration></configuration>\n' > "${HOME}/.config/NuGet/NuGet.Config"
    printf '<settings></settings>\n' > "${HOME}/.m2/settings.xml"
    printf 'registry=https://registry.npmjs.org/\n' > "${HOME}/.npmrc"
    printf 'export PATH=/usr/bin\n' > "${HOME}/.zshrc"

    run "$SCRIPT" --audit
    # Reaching the summary proves no mid-run abort from a routine no-match.
    assert_output --partial "Audit Summary"
    # The inventory found nothing in these marker-free files.
    assert_output --partial "No plaintext dev credentials detected"
}

# AC-19: tier does not leak from a prior section — only-hygiene findings keep
# TIER_SECURITY_ISSUES at 0 even though main() enters at ambient security.
@test "AC-19: hygiene-only inventory keeps TIER_SECURITY_ISSUES == 0" {
    source_functions
    set_tier security   # simulate ambient security tier from a prior section
    TIER_SECURITY_ISSUES=0
    TIER_HYGIENE_ISSUES=0
    mkdir -p "${HOME}/.gradle"
    printf 'signing.password=hunter2\n' > "${HOME}/.gradle/gradle.properties"
    printf 'export API_KEY=abc123\n' > "${HOME}/.zshrc"

    audit_secret_inventory
    assert_equal "$TIER_SECURITY_ISSUES" 0
    [ "$TIER_HYGIENE_ISSUES" -gt 0 ]
}

# AC-16: every content registry pattern yields identical rg↔grep verdicts.
@test "AC-16: registry patterns are rg/grep dialect-portable" {
    command -v rg >/dev/null 2>&1 || skip "rg not installed"
    source_functions

    # (pattern ~~~ fixture-line ~~~ expected-verdict 0=match 1=nomatch).
    # Fields are ~~~-delimited because several patterns contain a literal '|'.
    local cases=(
        'aws_secret_access_key~~~aws_secret_access_key=AKIA~~~0'
        'aws_secret_access_key~~~region=us-east-1~~~1'
        'access-token:~~~access-token: deadbeef~~~0'
        'oauth_token:~~~  oauth_token: gho_x~~~0'
        'token:~~~  token: glpat-x~~~0'
        '_authToken=[^[:space:]]~~~//r/:_authToken=npm_x~~~0'
        '_authToken=[^[:space:]]~~~//r/:_authToken=~~~1'
        '^[[:space:]]*npmAuthToken:[[:space:]]*[^[:space:]#]~~~  npmAuthToken: yarn_x~~~0'
        '^[[:space:]]*npmAuthToken:[[:space:]]*[^[:space:]#]~~~  npmAuthToken: # none~~~1'
        '^[[:space:]]*password[[:space:]]*=[[:space:]]*[^[:space:]]~~~password = secret~~~0'
        '^[[:space:]]*password[[:space:]]*=[[:space:]]*[^[:space:]]~~~password =~~~1'
        '://[^/[:space:]]+:[^@/[:space:]]+@~~~https://u:p@host/x~~~0'
        '://[^/[:space:]]+:[^@/[:space:]]+@~~~https://host/x~~~1'
        '<password>[^<$%]~~~<password>secret</password>~~~0'
        '<password>[^<$%]~~~<password></password>~~~1'
        '<password>[^<$%]~~~<password>${env.X}</password>~~~1'
        '"auth":[[:space:]]*"[^"]~~~"auth": "c2Vj"~~~0'
        '"auth":[[:space:]]*"[^"]~~~"auth": ""~~~1'
        '(client-key-data:[[:space:]]*[^[:space:]]|[[:space:]]token:[[:space:]]*[^[:space:]])~~~    client-key-data: AAA~~~0'
        '(client-key-data:[[:space:]]*[^[:space:]]|[[:space:]]token:[[:space:]]*[^[:space:]])~~~ token: tok~~~0'
        '(client-key-data:[[:space:]]*[^[:space:]]|[[:space:]]token:[[:space:]]*[^[:space:]])~~~apiVersion: v1~~~1'
        'password[[:space:]]*=~~~password=hunter2~~~0'
        'ClearTextPassword~~~<add ClearTextPassword="x"/>~~~0'
        '(password|signing\.(key|password)|apiKey)~~~signing.password=x~~~0'
        '(password|signing\.(key|password)|apiKey)~~~org.gradle.jvmargs=-Xmx2g~~~1'
        'credentials~~~  credentials "app" { token = "x" }~~~0'
    )

    local c pat line want fixture rg_rc grep_rc
    for c in "${cases[@]}"; do
        pat="${c%%~~~*}"
        local rest="${c#*~~~}"
        line="${rest%~~~*}"
        want="${rest##*~~~}"
        fixture="$(mktemp)"
        printf '%s\n' "$line" > "$fixture"

        rg_rc=0; LC_ALL=C rg --quiet --max-count=1 --no-config -e "$pat" -- "$fixture" || rg_rc=$?
        grep_rc=0; LC_ALL=C grep -qElm1 -e "$pat" -- "$fixture" || grep_rc=$?
        rm -f "$fixture"

        # Normalize to 0/1 (rg/grep both use 0 match, 1 no-match)
        [ "$rg_rc" -eq 0 ] || rg_rc=1
        [ "$grep_rc" -eq 0 ] || grep_rc=1

        assert_equal "$rg_rc" "$grep_rc"
        assert_equal "$rg_rc" "$want"
    done
}

# AC-17: rg-preferred, grep-fallback parity over a real finding.
@test "AC-17: identical findings with rg present and rg removed" {
    mkdir -p "${HOME}/.aws"
    printf 'aws_secret_access_key=AKIAabc\n' > "${HOME}/.aws/credentials"

    run "$SCRIPT" --audit
    local with_rg
    with_rg="$(printf '%s\n' "$output" | grep -F 'AWS static keys' || true)"

    # Remove rg from PATH and re-run; grep fallback must produce same finding.
    local stub_dir
    stub_dir="$(mktemp -d)"
    # Build a PATH that has everything except rg by symlinking needed tools.
    # Simpler: shadow rg with a non-executable name is not enough; instead set
    # a PATH containing only standard dirs but intercept rg via a failing stub
    # is wrong (would be found). We instead drop rg by pointing PATH at a dir
    # of symlinks excluding rg.
    local d
    for d in /bin /usr/bin /usr/local/bin /opt/homebrew/bin; do
        [ -d "$d" ] || continue
        for tool in bash sh grep sed awk git ssh ssh-keygen ssh-add stat uname mktemp head tr ls dirname basename cat; do
            [ -e "${d}/${tool}" ] && [ ! -e "${stub_dir}/${tool}" ] && ln -s "${d}/${tool}" "${stub_dir}/${tool}"
        done
    done
    run env PATH="$stub_dir" "$SCRIPT" --audit
    local no_rg
    no_rg="$(printf '%s\n' "$output" | grep -F 'AWS static keys' || true)"
    rm -rf "$stub_dir"

    refute [ -z "$with_rg" ]
    refute [ -z "$no_rg" ]
}

# Symlink content-scan gate: a symlinked content-file is reported by its link
# path (never silently dropped) but is NOT read through (no content scan).
@test "secret inventory: symlinked content-file reported, not read through" {
    source_functions
    mkdir -p "${HOME}/.aws"
    printf 'aws_secret_access_key=SENTINEL_LEAK_CHECK\n' > "${HOME}/realcreds"
    ln -s "${HOME}/realcreds" "${HOME}/.aws/credentials"

    run audit_secret_inventory
    # Spec FR1 'Symlinks' / Edge Cases: the link PATH is still reported.
    assert_output --partial "AWS static keys: ${HOME}/.aws/credentials"
    # ...but the target's value is never read through the link.
    refute_output --partial "SENTINEL_LEAK_CHECK"
}

# Same obligation for the Docker json-marker-style helper.
@test "secret inventory: symlinked docker config reported, not read through" {
    source_functions
    mkdir -p "${HOME}/.docker"
    printf '{"auths":{"r.io":{"auth":"SENTINEL_LEAK_CHECK"}}}\n' > "${HOME}/realdocker"
    ln -s "${HOME}/realdocker" "${HOME}/.docker/config.json"

    run audit_secret_inventory
    assert_output --partial "Docker registry auth"
    assert_output --partial "${HOME}/.docker/config.json"
    refute_output --partial "SENTINEL_LEAK_CHECK"
}

# A symlinked content-file with NO real credential is still reported (the link
# path is the finding; existence of the credential path is itself meaningful).
@test "secret inventory: symlinked content-file is a security finding" {
    source_functions
    mkdir -p "${HOME}/.aws"
    printf 'no secret here at all\n' > "${HOME}/realcreds"
    ln -s "${HOME}/realcreds" "${HOME}/.aws/credentials"

    run audit_secret_inventory
    assert_output --partial "AWS static keys: ${HOME}/.aws/credentials"
}

# ===========================================================================
# v0.8 Phase 2: Bounded .env / scanned-JSON walk + --scan-depth (FR2/FR5)
# ===========================================================================

# AC-6: default depth surfaces parent-level 0/1/2 and NOT level 3; --scan-depth
# 3 additionally surfaces the level-3 file. "Level" counts directory hops from
# $HOME to the file's parent (find-depth = parent-level + 1).
@test "AC-6: .env depth default surfaces levels 0-2, not level 3" {
    source_functions
    SCAN_DEPTH=2
    cd "$HOME"   # make cwd == HOME so the cwd scan dedups, not adds noise

    printf 'X=1\n' > "${HOME}/.env"                      # parent-level 0
    mkdir -p "${HOME}/projects"
    printf 'X=1\n' > "${HOME}/projects/.env"             # parent-level 1
    mkdir -p "${HOME}/projects/app"
    printf 'X=1\n' > "${HOME}/projects/app/.env"         # parent-level 2
    mkdir -p "${HOME}/a/b/c"
    printf 'X=1\n' > "${HOME}/a/b/c/.env"                # parent-level 3

    run audit_secret_walk
    assert_output --partial ".env file: ${HOME}/.env"
    assert_output --partial ".env file: ${HOME}/projects/.env"
    assert_output --partial ".env file: ${HOME}/projects/app/.env"
    refute_output --partial ".env file: ${HOME}/a/b/c/.env"
}

@test "AC-6: --scan-depth 3 additionally surfaces the level-3 .env" {
    source_functions
    SCAN_DEPTH=3
    cd "$HOME"

    printf 'X=1\n' > "${HOME}/.env"
    mkdir -p "${HOME}/projects/app"
    printf 'X=1\n' > "${HOME}/projects/app/.env"
    mkdir -p "${HOME}/a/b/c"
    printf 'X=1\n' > "${HOME}/a/b/c/.env"

    run audit_secret_walk
    assert_output --partial ".env file: ${HOME}/.env"
    assert_output --partial ".env file: ${HOME}/projects/app/.env"
    assert_output --partial ".env file: ${HOME}/a/b/c/.env"
}

# AC-6 lower boundary: --scan-depth 0 surfaces only $HOME/.env (parent-level 0).
@test "AC-6: --scan-depth 0 surfaces only the top-level .env" {
    source_functions
    SCAN_DEPTH=0
    cd "$HOME"

    printf 'X=1\n' > "${HOME}/.env"
    mkdir -p "${HOME}/projects"
    printf 'X=1\n' > "${HOME}/projects/.env"

    run audit_secret_walk
    assert_output --partial ".env file: ${HOME}/.env"
    refute_output --partial ".env file: ${HOME}/projects/.env"
}

# .env.example/.sample/.template/.dist are excluded — not findings.
@test "AC-6: .env.example/.sample/.template/.dist are excluded" {
    source_functions
    SCAN_DEPTH=2
    cd "$HOME"

    printf 'X=1\n' > "${HOME}/.env.example"
    printf 'X=1\n' > "${HOME}/.env.sample"
    printf 'X=1\n' > "${HOME}/.env.template"
    printf 'X=1\n' > "${HOME}/.env.dist"
    printf 'X=1\n' > "${HOME}/.env.production"   # .env.* (not excluded)

    run audit_secret_walk
    refute_output --partial ".env.example"
    refute_output --partial ".env.sample"
    refute_output --partial ".env.template"
    refute_output --partial ".env.dist"
    assert_output --partial ".env file: ${HOME}/.env.production"
}

# AC-9: a nested node_modules/.env is pruned, and the [INFO] coverage line
# names the depth and the pruned directories.
@test "AC-9: node_modules/.env is pruned and INFO line is printed" {
    source_functions
    SCAN_DEPTH=2
    cd "$HOME"

    mkdir -p "${HOME}/node_modules/dep"
    printf 'X=1\n' > "${HOME}/node_modules/dep/.env"
    printf 'X=1\n' > "${HOME}/.env"

    run audit_secret_walk
    refute_output --partial "node_modules/dep/.env"
    assert_output --partial ".env file: ${HOME}/.env"
    assert_output --partial "[INFO]"
    assert_output --partial "scanned ~/ to depth 2"
    assert_output --partial "node_modules"
}

# All fixed prune dirs are honored within depth.
@test "AC-9: the full prune allowlist is honored" {
    source_functions
    SCAN_DEPTH=2
    cd "$HOME"

    local d
    for d in node_modules .git vendor .cache .cargo .rustup .npm Library .Trash .terraform pkg; do
        mkdir -p "${HOME}/${d}/sub"
        printf 'X=1\n' > "${HOME}/${d}/sub/.env"
    done

    run audit_secret_walk
    refute_output --partial "/sub/.env"
}

# AC-10: --scan-depth abc dies cleanly with a usage error, non-zero exit, no
# arithmetic abort.
@test "AC-10: --scan-depth abc dies with usage error" {
    run "$SCRIPT" --scan-depth abc
    assert_failure
    assert_output --partial "non-negative integer"
}

# AC-10: --scan-depth -1 dies cleanly (negative is not ^[0-9]+$).
@test "AC-10: --scan-depth -1 dies with usage error" {
    run "$SCRIPT" --scan-depth -1
    assert_failure
    assert_output --partial "non-negative integer"
}

# A missing argument to --scan-depth also dies cleanly.
@test "AC-10: --scan-depth without an argument dies" {
    run "$SCRIPT" --scan-depth
    assert_failure
    assert_output --partial "requires"
}

# --scan-depth is documented in usage/--help.
@test "AC-10: --scan-depth is documented in --help" {
    run "$SCRIPT" --help
    assert_success
    assert_output --partial "--scan-depth"
}

# NUL-safe consumption: .env files whose parent directory name contains a space,
# a tab, or a newline are still discovered (find -print0 | read -d '').
@test "FR2: NUL-safe walk finds .env in dirs with space/tab/newline names" {
    source_functions
    SCAN_DEPTH=2
    cd "$HOME"

    mkdir -p "${HOME}/weird dir"
    printf 'X=1\n' > "${HOME}/weird dir/.env"

    local tabdir
    tabdir="$(printf 'tab\tdir')"
    mkdir -p "${HOME}/${tabdir}"
    printf 'X=1\n' > "${HOME}/${tabdir}/.env"

    local nldir
    nldir="$(printf 'nl\ndir')"
    mkdir -p "${HOME}/${nldir}"
    printf 'X=1\n' > "${HOME}/${nldir}/.env"

    run audit_secret_walk
    assert_output --partial ".env file: ${HOME}/weird dir/.env"
    assert_output --partial "${tabdir}/.env"
    # The newline-named dir splits across lines; assert both halves appear.
    assert_output --partial "nl"
    assert_output --partial "dir/.env"
}

# The current working directory's direct children are scanned at depth 0 even
# when cwd is OUTSIDE the $HOME subtree.
@test "FR2: cwd direct children are scanned even outside HOME" {
    source_functions
    SCAN_DEPTH=2

    local repo
    repo="$(mktemp -d)"
    printf 'X=1\n' > "${repo}/.env"
    cd "$repo"

    run audit_secret_walk
    assert_output --partial ".env file: ${repo}/.env"
    rm -rf "$repo"
}

# De-duplication: a .env reachable by both the $HOME walk and the cwd scan is
# reported exactly once (keyed by canonical path).
@test "FR2: a .env in both HOME walk and cwd scan is reported once" {
    source_functions
    SCAN_DEPTH=2

    mkdir -p "${HOME}/projects/app"
    printf 'X=1\n' > "${HOME}/projects/app/.env"
    cd "${HOME}/projects/app"

    run audit_secret_walk
    local count
    count="$(printf '%s\n' "$output" | grep -cF ".env file: ${HOME}/projects/app/.env")"
    assert_equal "$count" 1
}

# A scanned *.json that is a genuine GCP service-account key (two-pass marker)
# within depth is surfaced as a security finding via the walk.
@test "FR2: walk surfaces a GCP service-account .json within depth" {
    source_functions
    SCAN_DEPTH=2
    cd "$HOME"

    mkdir -p "${HOME}/projects/app"
    printf '{"type": "service_account", "private_key": "X"}\n' \
        > "${HOME}/projects/app/sa.json"

    run audit_secret_walk
    assert_output --partial "GCP service-account key: ${HOME}/projects/app/sa.json"
}

# A plain *.json with no service-account markers is not a finding.
@test "FR2: walk ignores a non-service-account .json" {
    source_functions
    SCAN_DEPTH=2
    cd "$HOME"

    mkdir -p "${HOME}/projects/app"
    printf '{"name": "app", "version": "1.0.0"}\n' \
        > "${HOME}/projects/app/package.json"

    run audit_secret_walk
    refute_output --partial "package.json"
}

# --scan-depth composes with --audit (no security-tier .env findings -> exit 0).
@test "FR5: --scan-depth composes with --audit (hygiene .env -> exit 0)" {
    printf 'X=1\n' > "${HOME}/.env"
    cd "$HOME"

    run "$SCRIPT" --audit --scan-depth 2
    # .env is hygiene-tier; a clean git config is the only thing that could
    # gate the exit, so assert the inventory ran and exit reflects hygiene-only.
    assert_output --partial ".env file: ${HOME}/.env"
}

# ===========================================================================
# v0.8 Phase 3: Permission audit + chmod 600 apply (FR3)
# ===========================================================================

# Detect the host stat dialect so file_mode/PLATFORM tests are deterministic.
host_platform() {
    case "$(uname -s)" in
        Darwin*) printf 'macos' ;;
        Linux*)  printf 'linux' ;;
        *)       printf 'linux' ;;
    esac
}

# file_mode returns the octal mode string and validates its format.
@test "file_mode returns the octal mode of a 644 file" {
    source_functions
    PLATFORM="$(host_platform)"
    printf 'x\n' > "${HOME}/f"
    chmod 644 "${HOME}/f"

    run file_mode "${HOME}/f"
    assert_success
    assert_output "644"
}

@test "file_mode returns 600 for an owner-only file" {
    source_functions
    PLATFORM="$(host_platform)"
    printf 'x\n' > "${HOME}/f"
    chmod 600 "${HOME}/f"

    run file_mode "${HOME}/f"
    assert_success
    assert_output "600"
}

# FR3 octal masking: a macOS-style no-leading-zero mode must be interpreted as
# octal, not decimal. secret_perm_check on a 640 file (group-readable) flags it.
@test "secret_perm_check flags a group-readable 640 file (no-leading-zero mode)" {
    source_functions
    PLATFORM="$(host_platform)"
    printf 'x\n' > "${HOME}/f"
    chmod 640 "${HOME}/f"
    SECRET_PERM_FLAGGED=()

    run secret_perm_check "${HOME}/f"
    assert_success
    assert_output --partial "is mode 640 (group/other readable)"
}

# A 600 file has no group/other bit set → no finding, not flagged.
@test "secret_perm_check does not flag a 600 file" {
    source_functions
    PLATFORM="$(host_platform)"
    printf 'x\n' > "${HOME}/f"
    chmod 600 "${HOME}/f"
    SECRET_PERM_FLAGGED=()

    secret_perm_check "${HOME}/f"
    assert_equal "${#SECRET_PERM_FLAGGED[@]}" 0
}

# FR3 masking on a 4-digit (setuid-style) mode: 4644 → low 3 digits 644 →
# group/other readable → flagged. Proves the leading-zero strip + low-3-digit
# mask is correct, and that a decimal interpretation would be wrong.
@test "secret_perm_check masks a 4-digit mode correctly" {
    source_functions
    PLATFORM="linux"

    # Stub file_mode to return a 4-digit mode without needing a real setuid file
    # (setuid on a plain file is unreliable across CI filesystems).
    file_mode() { printf '4644\n'; }
    printf 'x\n' > "${HOME}/f"
    SECRET_PERM_FLAGGED=()

    run secret_perm_check "${HOME}/f"
    assert_success
    assert_output --partial "is mode 4644 (group/other readable)"
}

# A 4-digit mode whose low 3 digits are owner-only (e.g. 4600) is NOT flagged.
@test "secret_perm_check 4-digit owner-only mode is not flagged" {
    source_functions
    PLATFORM="linux"
    file_mode() { printf '4600\n'; }
    printf 'x\n' > "${HOME}/f"
    SECRET_PERM_FLAGGED=()

    secret_perm_check "${HOME}/f"
    assert_equal "${#SECRET_PERM_FLAGGED[@]}" 0
}

# A leading-zero (0600) mode strips correctly and is not flagged.
@test "secret_perm_check leading-zero 0600 mode is not flagged" {
    source_functions
    PLATFORM="linux"
    file_mode() { printf '0600\n'; }
    printf 'x\n' > "${HOME}/f"
    SECRET_PERM_FLAGGED=()

    secret_perm_check "${HOME}/f"
    assert_equal "${#SECRET_PERM_FLAGGED[@]}" 0
}

# file_mode failure path: a stat that produces junk → caller WARNs and skips,
# the finding is not added to the flagged list, and the run does not abort.
@test "secret_perm_check WARNs and skips on unparseable mode" {
    source_functions
    PLATFORM="linux"
    file_mode() { return 1; }   # simulate stat unavailable / bad output
    printf 'x\n' > "${HOME}/f"
    SECRET_PERM_FLAGGED=()

    run secret_perm_check "${HOME}/f"
    assert_success
    assert_output --partial "could not determine permissions"
    # Confirm it did not record a flagged file.
    SECRET_PERM_FLAGGED=()
    file_mode() { return 1; }
    secret_perm_check "${HOME}/f"
    assert_equal "${#SECRET_PERM_FLAGGED[@]}" 0
}

# secret_perm_check de-duplicates a file surfaced twice.
@test "secret_perm_check de-duplicates a repeated file" {
    source_functions
    PLATFORM="$(host_platform)"
    printf 'x\n' > "${HOME}/f"
    chmod 644 "${HOME}/f"
    SECRET_PERM_FLAGGED=()

    secret_perm_check "${HOME}/f"
    secret_perm_check "${HOME}/f"
    assert_equal "${#SECRET_PERM_FLAGGED[@]}" 1
}

# AC-4 (interactive accept): a 644 ~/.pgpass is flagged by the inventory and the
# apply phase chmods it to 600 when the user accepts the grouped prompt.
@test "AC-4: pgpass 644 -> 600 via interactive accept" {
    source_functions
    PLATFORM="$(host_platform)"
    printf 'localhost:5432:db:user:secret\n' > "${HOME}/.pgpass"
    chmod 644 "${HOME}/.pgpass"

    audit_secret_inventory
    # Inventory recorded the group-readable .pgpass as a flagged file.
    [ "${#SECRET_PERM_FLAGGED[@]}" -ge 1 ]

    # Simulate the interactive default-Yes accept.
    prompt_yn() { return 0; }
    apply_secret_permissions

    run file_mode "${HOME}/.pgpass"
    assert_output "600"
}

# AC-4 (-y auto): the same fix is applied automatically under -y, no prompt.
@test "AC-4: pgpass 644 -> 600 automatically under -y" {
    source_functions
    PLATFORM="$(host_platform)"
    AUTO_YES=true
    printf 'localhost:5432:db:user:secret\n' > "${HOME}/.pgpass"
    chmod 644 "${HOME}/.pgpass"

    audit_secret_inventory
    apply_secret_permissions

    run file_mode "${HOME}/.pgpass"
    assert_output "600"
}

# Interactive decline leaves the mode unchanged.
@test "AC-4: declining the prompt leaves permissions unchanged" {
    source_functions
    PLATFORM="$(host_platform)"
    printf 'localhost:5432:db:user:secret\n' > "${HOME}/.pgpass"
    chmod 644 "${HOME}/.pgpass"

    audit_secret_inventory
    prompt_yn() { return 1; }
    apply_secret_permissions

    run file_mode "${HOME}/.pgpass"
    assert_output "644"
}

# A 600 secret file is not flagged and the apply phase is a no-op.
@test "AC-4: an already-600 secret produces no permission prompt" {
    source_functions
    PLATFORM="$(host_platform)"
    printf 'localhost:5432:db:user:secret\n' > "${HOME}/.pgpass"
    chmod 600 "${HOME}/.pgpass"

    audit_secret_inventory
    assert_equal "${#SECRET_PERM_FLAGGED[@]}" 0

    run apply_secret_permissions
    assert_success
    refute_output --partial "Secret File Permissions"
}

# AC-5: a flagged file that cannot be chmod'd (simulated not-owned) is skipped
# with a [WARN] and the run continues to completion without aborting.
@test "AC-5: chmod skips a non-owned file without aborting" {
    source_functions
    PLATFORM="$(host_platform)"
    AUTO_YES=true

    # Two flagged files: one fixable, one we make "not owned" by stubbing the
    # ownership test. We stub via a wrapper: override the [[ -O ]] outcome by
    # marking the file path and intercepting in a custom apply is complex, so we
    # instead drop write permission on the parent dir for one file path that no
    # longer exists, making it not a regular file -> skipped. Simpler and
    # portable: flag a directory (never a regular file) alongside a real file.
    printf 'x\n' > "${HOME}/good"
    chmod 644 "${HOME}/good"
    mkdir -p "${HOME}/notafile"
    SECRET_PERM_FLAGGED=("${HOME}/notafile" "${HOME}/good")

    run apply_secret_permissions
    assert_success
    assert_output --partial "Skipped ${HOME}/notafile"
    # The genuine file was still fixed despite the skip.
    run file_mode "${HOME}/good"
    assert_output "600"
}

# AC-5 symlink: a flagged symlink is skipped (never chmod'd through the link).
@test "AC-5: chmod skips a symlink target" {
    source_functions
    PLATFORM="$(host_platform)"
    AUTO_YES=true
    printf 'x\n' > "${HOME}/realfile"
    chmod 644 "${HOME}/realfile"
    ln -s "${HOME}/realfile" "${HOME}/linkfile"
    SECRET_PERM_FLAGGED=("${HOME}/linkfile")

    run apply_secret_permissions
    assert_success
    assert_output --partial "Skipped ${HOME}/linkfile: is a symlink"
    # The link target's mode is untouched.
    run file_mode "${HOME}/realfile"
    assert_output "644"
}

# apply_secret_permissions is a clean no-op when nothing was flagged.
@test "apply_secret_permissions no-op when nothing flagged" {
    source_functions
    SECRET_PERM_FLAGGED=()
    run apply_secret_permissions
    assert_success
    assert_output ""
}

# secret_perm_check ignores directories (never a chmod-600 target).
@test "secret_perm_check ignores directories" {
    source_functions
    PLATFORM="$(host_platform)"
    mkdir -p "${HOME}/d"
    chmod 755 "${HOME}/d"
    SECRET_PERM_FLAGGED=()

    secret_perm_check "${HOME}/d"
    assert_equal "${#SECRET_PERM_FLAGGED[@]}" 0
}

# End-to-end FR3: --audit never chmods (read-only) but still reports the mode.
@test "FR3: --audit reports the group-readable mode but does not chmod" {
    printf 'localhost:5432:db:user:secret\n' > "${HOME}/.pgpass"
    chmod 644 "${HOME}/.pgpass"

    run "$SCRIPT" --audit
    assert_output --partial "is mode 644 (group/other readable)"

    # Read-only: the file mode is unchanged after an --audit run.
    local after
    case "$(uname -s)" in
        Darwin*) after="$(stat -f '%Lp' "${HOME}/.pgpass")" ;;
        *)       after="$(stat -c '%a' "${HOME}/.pgpass")" ;;
    esac
    assert_equal "$after" "644"
}

# ===========================================================================
# v0.8 Phase 4: 1Password migration advisor (FR4)
# ===========================================================================

# Build a stub dir holding a fake `op` (and the real tools the advisor needs)
# and put it FIRST on PATH so `command -v op` succeeds. Echoes the dir.
make_op_stub_dir() {
    local d
    d="$(mktemp -d)"
    printf '#!/bin/sh\nexit 0\n' > "${d}/op"
    chmod +x "${d}/op"
    printf '%s' "$d"
}

# A clean PATH containing the tools the advisor needs but NOT `op`, so
# `command -v op` fails deterministically regardless of the host. Echoes it.
make_op_absent_path() {
    local d
    d="$(mktemp -d)"
    local src tool
    for src in /bin /usr/bin /usr/local/bin /opt/homebrew/bin; do
        [ -d "$src" ] || continue
        for tool in bash sh grep sed awk git ssh ssh-keygen ssh-add stat uname \
                    mktemp head tr ls dirname basename cat realpath find chmod rg; do
            [ -e "${src}/${tool}" ] && [ "$tool" != "op" ] && \
                [ ! -e "${d}/${tool}" ] && ln -s "${src}/${tool}" "${d}/${tool}"
        done
    done
    printf '%s' "$d"
}

# AC-8: op present on PATH -> the AWS finding yields `op plugin init aws`.
@test "AC-8: op present prints 'op plugin init aws' for an AWS finding" {
    mkdir -p "${HOME}/.aws"
    printf 'aws_secret_access_key=AKIAexample\n' > "${HOME}/.aws/credentials"

    local stub
    stub="$(make_op_stub_dir)"
    run env PATH="${stub}:${PATH}" "$SCRIPT" --audit
    rm -rf "$stub"

    assert_output --partial "op plugin init aws"
    assert_output --partial "1Password Migration Advisor"
}

# AC-8: op absent -> the install pointer URL prints AND the per-finding step
# (op plugin init aws) still prints.
@test "AC-8: op absent prints install URL and still prints the per-finding step" {
    mkdir -p "${HOME}/.aws"
    printf 'aws_secret_access_key=AKIAexample\n' > "${HOME}/.aws/credentials"

    local cleanpath
    cleanpath="$(make_op_absent_path)"
    run env PATH="$cleanpath" "$SCRIPT" --audit
    rm -rf "$cleanpath"

    assert_output --partial "https://developer.1password.com/docs/cli/get-started/"
    assert_output --partial "op plugin init aws"
}

# When op is absent the advisor prints a concrete install COMMAND, not just a
# URL ("brew install 1password-cli" appears on both macOS and Linux via the
# Homebrew line).
@test "AC-8: op absent prints a concrete install command" {
    mkdir -p "${HOME}/.aws"
    printf 'aws_secret_access_key=AKIAexample\n' > "${HOME}/.aws/credentials"

    local cleanpath
    cleanpath="$(make_op_absent_path)"
    run env PATH="$cleanpath" "$SCRIPT" --audit
    rm -rf "$cleanpath"

    assert_output --partial "Install the 1Password CLI (op):"
    assert_output --partial "brew install 1password-cli"
}

# The advisor shows BOTH halves of the workflow: store the secret in 1Password
# (op item create) and use it via op (read/run) — independent of op presence.
@test "advisor prints both store (op item create) and use (op read/run) steps" {
    mkdir -p "${HOME}/.aws"
    printf 'aws_secret_access_key=AKIAexample\n' > "${HOME}/.aws/credentials"

    local cleanpath
    cleanpath="$(make_op_absent_path)"
    run env PATH="$cleanpath" "$SCRIPT" --audit
    rm -rf "$cleanpath"

    assert_output --partial "op item create"
    assert_output --partial "op read"
    assert_output --partial "op run"
}

# AC-8: a config-file CLI (kubeconfig) prints the op inject/op run example
# marked with the idiomatic-confirmation note.
@test "AC-8: config-file finding prints op example with idiomatic note" {
    mkdir -p "${HOME}/.kube"
    printf 'users:\n- user:\n    token: abc123\n' > "${HOME}/.kube/config"

    local stub
    stub="$(make_op_stub_dir)"
    run env PATH="${stub}:${PATH}" "$SCRIPT" --audit
    rm -rf "$stub"

    assert_output --partial "op inject"
    assert_output --partial "‡ idiomatic — confirm with op --help"
}

# The advisor prints nothing when the inventory found no credentials.
@test "AC-8: advisor prints nothing when no credentials are found" {
    local stub
    stub="$(make_op_stub_dir)"
    run env PATH="${stub}:${PATH}" "$SCRIPT" --audit
    rm -rf "$stub"

    refute_output --partial "1Password Migration Advisor"
    assert_output --partial "No plaintext dev credentials detected"
}

# AC-11: the Docker (obfuscated) advisor finding still uses the inventory's
# "recoverable by any local process" wording, never "plaintext."
@test "AC-11: docker finding uses 'recoverable by any local process' wording" {
    mkdir -p "${HOME}/.docker"
    printf '{"auths":{"reg":{"auth":"c2VjcmV0"}}}\n' > "${HOME}/.docker/config.json"

    local stub
    stub="$(make_op_stub_dir)"
    run env PATH="${stub}:${PATH}" "$SCRIPT" --audit
    rm -rf "$stub"

    assert_output --partial "recoverable by any local process"
    refute_output --partial "Docker registry auth (plaintext"
}

# AC-12: gitignore cross-reference — a detected .env whose basename is in the
# managed core.excludesFile gets the "(also gitignored)" note in the advisor.
@test "AC-12: advisor notes a .env that is also gitignored" {
    printf '.env\n*.pem\n' > "${HOME}/.config/git/ignore"
    git config --global core.excludesFile "${HOME}/.config/git/ignore"
    printf 'API_KEY=abc123\n' > "${HOME}/.env"

    local stub
    stub="$(make_op_stub_dir)"
    run env PATH="${stub}:${PATH}" "$SCRIPT" --audit
    rm -rf "$stub"

    assert_output --partial "(also gitignored)"
}

# AC-12 negative: with no .env pattern in the excludes file, the advisor does
# NOT claim the .env is gitignored.
@test "AC-12: advisor does not claim gitignored when pattern absent" {
    printf '*.pem\n' > "${HOME}/.config/git/ignore"
    git config --global core.excludesFile "${HOME}/.config/git/ignore"
    printf 'API_KEY=abc123\n' > "${HOME}/.env"

    local stub
    stub="$(make_op_stub_dir)"
    run env PATH="${stub}:${PATH}" "$SCRIPT" --audit
    rm -rf "$stub"

    refute_output --partial "(also gitignored)"
}

# A shell-plugin CLI surfaced by two files (terraformrc + credentials.tfrc.json)
# yields a single `op plugin init terraform` block (de-duplicated by CLI).
@test "advisor de-duplicates a shell-plugin CLI across files" {
    mkdir -p "${HOME}/.terraform.d"
    printf '{"credentials":{}}\n' > "${HOME}/.terraform.d/credentials.tfrc.json"
    printf 'credentials "app.terraform.io" {\n  token = "x"\n}\n' > "${HOME}/.terraformrc"

    local stub
    stub="$(make_op_stub_dir)"
    run env PATH="${stub}:${PATH}" "$SCRIPT" --audit
    rm -rf "$stub"

    local count
    count="$(printf '%s\n' "$output" | grep -cF 'op plugin init terraform' || true)"
    assert_equal "$count" 1
}

# No-leak: the advisor never echoes a secret value (it only reads SECRET_FINDINGS
# paths/keys, never re-reads the credential file).
@test "advisor output never contains a planted secret value" {
    mkdir -p "${HOME}/.aws"
    printf 'aws_secret_access_key=SENTINEL_LEAK_CHECK\n' > "${HOME}/.aws/credentials"

    local stub
    stub="$(make_op_stub_dir)"
    run env PATH="${stub}:${PATH}" "$SCRIPT" --audit
    rm -rf "$stub"

    refute_output --partial "SENTINEL_LEAK_CHECK"
    assert_output --partial "op plugin init aws"
}

# ===========================================================================
# v0.8.1 — post-review regression fixes (final Daria holistic review)
# ===========================================================================

@test "secret inventory: GPG-only machine does not print a false all-clear" {
    source_functions
    mkdir -p "${HOME}/.gnupg/private-keys-v1.d"
    printf 'dummy-key-material\n' > "${HOME}/.gnupg/private-keys-v1.d/ABCD1234.key"

    run audit_secret_inventory
    assert_output --partial "GPG private keys present"
    # The all-clear must NOT appear when an info-tier finding was recorded.
    refute_output --partial "No plaintext dev credentials detected"
}

@test "audit_signing pins the security tier regardless of ambient (sticky) tier" {
    source_functions
    # Simulate a prior section having left the sticky tier at hygiene; a
    # signing misconfiguration must still be counted as a security issue.
    set +o errexit
    set_tier hygiene
    TIER_SECURITY_ISSUES=0
    audit_signing >/dev/null 2>&1
    set -o errexit
    [ "$TIER_SECURITY_ISSUES" -gt 0 ]
}

# ===========================================================================
# Admin recommendations: signing items gated on an actual signing key
# ===========================================================================

@test "admin recs: signing-specific items hidden when no signing key is configured" {
    source_functions
    git config --global --unset user.signingkey 2>/dev/null || true

    run print_admin_recommendations
    assert_success
    # Non-signing org guidance always shows.
    assert_output --partial "branch protection rules on main branches"
    # Signing-specific items must NOT appear.
    refute_output --partial "Flag unsigned commits"
    refute_output --partial "Require signed commits via branch protection"
    refute_output --partial "separate signing keys per org"
}

@test "admin recs: signing-specific items shown when a signing key is configured" {
    source_functions
    git config --global user.signingkey "key::ssh-ed25519 AAAATESTBLOB test@example.com"

    run print_admin_recommendations
    assert_success
    assert_output --partial "branch protection rules on main branches"
    assert_output --partial "Flag unsigned commits"
    assert_output --partial "Require signed commits via branch protection"
    assert_output --partial "separate signing keys per org"
}

# ===========================================================================
# Advisor: credential-helper files (.git-credentials, .netrc) get the
# switch-the-backend guidance, not the misleading generic op-read advice.
# ===========================================================================

@test "advisor: .git-credentials advises switching the credential helper (not op read)" {
    printf 'https://user:SENTINEL_LEAK_CHECK@github.com\n' > "${HOME}/.git-credentials"

    local cleanpath
    cleanpath="$(make_op_absent_path)"
    run env PATH="$cleanpath" "$SCRIPT" --audit
    rm -rf "$cleanpath"

    assert_output --partial "credential.helper"
    assert_output --partial "Migrate the credential HELPER"
    # The misleading generic vault-item path for THIS file must not appear.
    refute_output --partial 'op://vault/.git-credentials/credential'
    refute_output --partial "SENTINEL_LEAK_CHECK"
}

@test "advisor: .netrc advises a keychain helper for git plus op inject for other tools" {
    printf 'machine github.com\nlogin user\npassword SENTINEL_LEAK_CHECK\n' > "${HOME}/.netrc"

    local cleanpath
    cleanpath="$(make_op_absent_path)"
    run env PATH="$cleanpath" "$SCRIPT" --audit
    rm -rf "$cleanpath"

    assert_output --partial "credential.helper"
    assert_output --partial "op inject"
    refute_output --partial "SENTINEL_LEAK_CHECK"
}

# ===========================================================================
# Signing key picker: list any agent/disk key, hardware-backed (sk) first
# ===========================================================================

@test "list_signing_candidates: on-disk modern keys, hardware-backed (sk) first" {
    source_functions
    unset SSH_AUTH_SOCK SSH_AGENT_PID   # deterministic: no agent

    ssh-keygen -t ed25519 -f "${HOME}/.ssh/id_ed25519" -C "soft@host" -N "" -q
    # Craft an sk public-key stub (real -sk generation needs hardware).
    printf 'sk-ssh-ed25519@openssh.com AAAAfakeskblob hw@host\n' > "${HOME}/.ssh/id_ed25519_sk.pub"

    run list_signing_candidates
    assert_success
    # The hardware-backed key is listed before the software key.
    [[ "${lines[0]}" == *"sk-ssh-ed25519"* ]]
    assert_output --partial "id_ed25519.pub"
    assert_output --partial "id_ed25519_sk.pub"
    # Both are disk candidates.
    assert_output --partial $'disk\t1\t'
    assert_output --partial $'disk\t0\t'
}

@test "list_signing_candidates: a colima-style IdentityFile key is selectable, RSA excluded" {
    source_functions
    unset SSH_AUTH_SOCK SSH_AGENT_PID

    # A non-~/.ssh key referenced via IdentityFile (the colima case).
    mkdir -p "${HOME}/elsewhere"
    ssh-keygen -t ed25519 -f "${HOME}/elsewhere/colima" -C "colima" -N "" -q
    printf 'IdentityFile %s/elsewhere/colima\n' "${HOME}" > "${HOME}/.ssh/config"
    # A legacy RSA key that must NOT appear in the modern picker.
    ssh-keygen -t rsa -b 2048 -f "${HOME}/.ssh/id_rsa" -N "" -q

    run list_signing_candidates
    assert_success
    assert_output --partial "elsewhere/colima.pub"
    refute_output --partial "id_rsa"
}

@test "list_signing_candidates: empty when no modern keys anywhere" {
    source_functions
    unset SSH_AUTH_SOCK SSH_AGENT_PID
    run list_signing_candidates
    assert_success
    assert_output ""
}

# ===========================================================================
# Agent-aware signing: the chosen key's holding agent is tracked so signing
# and verification target the RIGHT agent (git signs via SSH_AUTH_SOCK).
# ===========================================================================

@test "agent_socket_for_blob: finds the socket holding a key, empty for unknown" {
    source_functions
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k" -N "" -q
    ssh-add "${TEST_HOME}/k" >/dev/null 2>&1
    local blob
    blob="$(awk '{print $2}' "${TEST_HOME}/k.pub")"

    run agent_socket_for_blob "$blob"
    assert_success
    assert_output "$SSH_AUTH_SOCK"

    run agent_socket_for_blob "AAAAnot-a-real-blob"
    assert_success
    assert_output ""
}

@test "list_signing_candidates: agent key carries its socket and agent-type label" {
    source_functions
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k" -C "vault@host" -N "" -q
    ssh-add "${TEST_HOME}/k" >/dev/null 2>&1

    run list_signing_candidates
    assert_success
    # Record carries the holding socket as the 5th field, and labels the agent.
    assert_output --partial "$SSH_AUTH_SOCK"
    assert_output --partial "[agent:"
}

@test "enable_signing_agent_key warns when the key's agent is not SSH_AUTH_SOCK" {
    source_functions
    AUTO_YES=true   # skip the interactive smoke test
    unset SSH_AUTH_SOCK SSH_AGENT_PID
    ssh-keygen -t ed25519 -f "${TEST_HOME}/k" -N "" -q
    local pub
    pub="$(cat "${TEST_HOME}/k.pub")"

    # Pass an explicit holding socket that differs from (unset) SSH_AUTH_SOCK.
    run enable_signing_agent_key "$pub" "/run/bitwarden-ssh-agent.sock"
    assert_success
    assert_output --partial "git signs commits via SSH_AUTH_SOCK"
    assert_output --partial "export SSH_AUTH_SOCK=/run/bitwarden-ssh-agent.sock"
}

@test "apply_identity_agent_offer: prefers the agent holding the signing key" {
    source_functions
    AUTO_YES=true
    : > "${HOME}/.ssh/config"
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/sk" -N "" -q
    ssh-add "${TEST_HOME}/sk" >/dev/null 2>&1
    local pub
    pub="$(cat "${TEST_HOME}/sk.pub")"
    git config --global user.signingkey "key::${pub}"
    # The agent holding the key is detectable as the Bitwarden socket; current
    # SSH_AUTH_SOCK is unset, so the preferred agent should be offered.
    ln -s "$SSH_AUTH_SOCK" "${HOME}/.bitwarden-ssh-agent.sock"
    unset SSH_AUTH_SOCK

    run apply_identity_agent_offer
    assert_success
    assert_output --partial "holds your signing key"
    grep -q "IdentityAgent ${HOME}/.bitwarden-ssh-agent.sock" "${HOME}/.ssh/config"
}

@test "apply_identity_agent_offer: offers to fix a mismatched existing IdentityAgent" {
    source_functions
    AUTO_YES=true   # accepts the (default-No) fix prompt
    start_test_agent
    ssh-keygen -t ed25519 -f "${TEST_HOME}/sk" -N "" -q
    ssh-add "${TEST_HOME}/sk" >/dev/null 2>&1
    local pub
    pub="$(cat "${TEST_HOME}/sk.pub")"
    git config --global user.signingkey "key::${pub}"
    ln -s "$SSH_AUTH_SOCK" "${HOME}/.bitwarden-ssh-agent.sock"
    unset SSH_AUTH_SOCK
    cat > "${HOME}/.ssh/config" <<'SSHEOF'
IdentityAgent /wrong/agent.sock
SSHEOF

    run apply_identity_agent_offer
    assert_success
    assert_output --partial "lives in the agent at"
    grep -q "IdentityAgent ${HOME}/.bitwarden-ssh-agent.sock" "${HOME}/.ssh/config"
}
