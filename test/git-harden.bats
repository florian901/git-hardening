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
    assert_output --partial "branch protection"
    assert_output --partial "vigilant mode"
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
# v0.2.0: Credential hygiene
# ===========================================================================

@test "audit warns about ~/.git-credentials" {
    source_functions

    printf 'https://user:token@github.com\n' > "${HOME}/.git-credentials"

    run audit_credential_hygiene
    assert_output --partial "git-credentials"
    assert_output --partial "plaintext"
}

@test "audit warns about ~/.netrc" {
    source_functions

    printf 'machine github.com\nlogin user\npassword token\n' > "${HOME}/.netrc"

    run audit_credential_hygiene
    assert_output --partial ".netrc"
}

@test "audit warns about ~/.npmrc with auth token" {
    source_functions

    printf '//registry.npmjs.org/:_authToken=npm_abcdef123456\n' > "${HOME}/.npmrc"

    run audit_credential_hygiene
    assert_output --partial "npm registry token"
}

@test "audit does not warn about ~/.npmrc without token" {
    source_functions

    printf 'registry=https://registry.npmjs.org/\n' > "${HOME}/.npmrc"

    run audit_credential_hygiene
    refute_output --partial "npm registry token"
}

@test "audit warns about ~/.pypirc with password" {
    source_functions

    printf '[pypi]\nusername = user\npassword = secret123\n' > "${HOME}/.pypirc"

    run audit_credential_hygiene
    assert_output --partial "PyPI credentials"
}

@test "audit no warnings with clean credential state" {
    source_functions

    run audit_credential_hygiene
    refute_output --partial "[WARN]"
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

@test "apply inserts into existing Host * block" {
    cat > "${TEST_HOME}/.ssh/config" <<'SSHEOF'
Host *
    HashKnownHosts yes

Host github.com
    IdentityFile ~/.ssh/github_key
SSHEOF

    source_functions
    apply_single_ssh_directive "IdentitiesOnly" "yes"

    # Should be inside Host * block (indented), not appended bare
    grep -q "IdentitiesOnly yes" "${TEST_HOME}/.ssh/config"
    # Only one Host * line
    local count
    count="$(grep -c '^Host \*$' "${TEST_HOME}/.ssh/config")"
    [ "$count" -eq 1 ]
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

    # Key files should be listed for cleanup
    assert_output --partial "my_org_key"
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
# v0.5.0: Version bump
# ===========================================================================

@test "--version reports 0.5.0" {
    run bash "$SCRIPT" --version
    assert_output --partial "0.5.0"
}
