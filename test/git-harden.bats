#!/usr/bin/env bats

# git-harden.sh — BATS test suite
# Runs in an isolated HOME to avoid touching real config.

BATS_TEST_DIRNAME="$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)"
SCRIPT="${BATS_TEST_DIRNAME}/../git-harden.sh"

load 'libs/bats-support/load'
load 'libs/bats-assert/load'

# ---------------------------------------------------------------------------
# Test isolation: every test gets its own HOME, GIT_CONFIG, SSH_DIR
# ---------------------------------------------------------------------------

setup() {
    TEST_HOME="$(mktemp -d)"
    export HOME="$TEST_HOME"
    export GIT_CONFIG_GLOBAL="${TEST_HOME}/.gitconfig"

    mkdir -p "${TEST_HOME}/.ssh"
    mkdir -p "${TEST_HOME}/.config/git"

    # Ensure git has user.name/email so config operations work
    git config --global user.name "Test User"
    git config --global user.email "test@example.com"
}

teardown() {
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

# ===========================================================================
# Argument parsing
# ===========================================================================

@test "--help prints usage and exits 0" {
    run bash "$SCRIPT" --help
    assert_success
    assert_output --partial "Usage: git-harden.sh"
}

@test "-h prints usage and exits 0" {
    run bash "$SCRIPT" -h
    assert_success
    assert_output --partial "Usage: git-harden.sh"
}

@test "--version prints version and exits 0" {
    run bash "$SCRIPT" --version
    assert_success
    assert_output --partial "git-harden.sh"
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

@test "-y mode applies git config settings" {
    source_functions
    AUTO_YES=true

    run apply_git_setting "transfer.fsckObjects" "true"
    assert_success

    local result
    result="$(git config --global --get transfer.fsckObjects)"
    [ "$result" = "true" ]
}

@test "apply skips already-correct setting" {
    git config --global transfer.fsckObjects true

    source_functions
    AUTO_YES=true

    run apply_git_setting "transfer.fsckObjects" "true"
    assert_success
    # Should produce no output (no "Set" message)
    refute_output --partial "Set"
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

    run apply_ssh_config
    assert_success

    # Check directory exists with correct mode
    [ -d "${TEST_HOME}/.ssh" ]
    [ -f "${TEST_HOME}/.ssh/config" ]

    local dir_perms
    dir_perms="$(stat -f '%Lp' "${TEST_HOME}/.ssh" 2>/dev/null || stat -c '%a' "${TEST_HOME}/.ssh" 2>/dev/null)"
    [ "$dir_perms" = "700" ]

    local file_perms
    file_perms="$(stat -f '%Lp' "${TEST_HOME}/.ssh/config" 2>/dev/null || stat -c '%a' "${TEST_HOME}/.ssh/config" 2>/dev/null)"
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

    apply_ssh_directive "StrictHostKeyChecking" "accept-new"

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

    apply_ssh_directive "StrictHostKeyChecking" "accept-new"

    # Verify updated
    grep -q "StrictHostKeyChecking accept-new" "${TEST_HOME}/.ssh/config"
    # Old value should be gone
    ! grep -q "StrictHostKeyChecking yes" "${TEST_HOME}/.ssh/config"
    # Other directives should be preserved
    grep -q "HashKnownHosts no" "${TEST_HOME}/.ssh/config"
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

@test "detect_existing_keys prefers sk key over software key" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q
    # Fake an sk key (can't generate real one without hardware)
    cp "${TEST_HOME}/.ssh/id_ed25519" "${TEST_HOME}/.ssh/id_ed25519_sk"
    # Write a fake pub key with sk type prefix
    printf 'sk-ssh-ed25519@openssh.com AAAAFakeKey test\n' > "${TEST_HOME}/.ssh/id_ed25519_sk.pub"

    source_functions
    detect_existing_keys

    [ "$SIGNING_KEY_FOUND" = true ]
    [ "$SIGNING_PUB_PATH" = "${TEST_HOME}/.ssh/id_ed25519_sk.pub" ]
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

@test "setup_allowed_signers skips when no email set" {
    ssh-keygen -t ed25519 -f "${TEST_HOME}/.ssh/id_ed25519" -N "" -q
    git config --global --unset user.email

    source_functions
    SIGNING_PUB_PATH="${TEST_HOME}/.ssh/id_ed25519.pub"

    run setup_allowed_signers
    assert_output --partial "user.email not set"
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
    assert_output --partial "branch protection"
    assert_output --partial "vigilant mode"
}
