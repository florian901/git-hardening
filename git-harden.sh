#!/usr/bin/env bash
# git-harden.sh — Audit and harden global git configuration
# Usage: git-harden.sh [--audit] [-y] [--reset-signing] [--help]

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
readonly VERSION="0.6.0"
readonly BACKUP_DIR="${HOME}/.config/git"
readonly HOOKS_DIR="${HOME}/.config/git/hooks"
readonly ALLOWED_SIGNERS_FILE="${HOME}/.config/git/allowed_signers"
readonly GLOBAL_GITIGNORE="${HOME}/.config/git/ignore"
readonly SSH_DIR="${HOME}/.ssh"
readonly SSH_CONFIG="${SSH_DIR}/config"

readonly PUBKEY_ALGO_LIST="ssh-ed25519,sk-ssh-ed25519@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com"

# Client-side hooks that get a dispatch stub when core.hooksPath is redirected,
# so repo-local hooks (.git/hooks/) keep working. pre-commit is handled
# separately (gitleaks + dispatch combined).
readonly DISPATCH_HOOK_NAMES=(
    applypatch-msg pre-applypatch post-applypatch
    pre-merge-commit prepare-commit-msg commit-msg post-commit
    pre-rebase post-checkout post-merge pre-push post-rewrite
    pre-auto-gc sendemail-validate post-index-change
)

# Color codes (empty if not a terminal)
if [ -t 2 ]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[0;33m'
    readonly BLUE='\033[0;34m'
    readonly BOLD='\033[1m'
    readonly RESET='\033[0m'
else
    readonly RED=''
    readonly GREEN=''
    readonly YELLOW=''
    readonly BLUE=''
    readonly BOLD=''
    readonly RESET=''
fi

# Mode flags (mutable — set by parse_args)
AUTO_YES=false
AUDIT_ONLY=false
RESET_SIGNING=false
PLATFORM=""

# Audit counters
AUDIT_OK=0
AUDIT_WARN=0
AUDIT_MISS=0

# Per-tier issue counters. Every audited item belongs to one tier:
#   security   — protects against a concrete attack vector
#   hygiene    — operational robustness / forensic readiness
#   preference — ecosystem alignment, no security impact
# Only security-tier issues drive the --audit exit code.
AUDIT_TIER="security"
TIER_SECURITY_ISSUES=0
TIER_HYGIENE_ISSUES=0
TIER_PREFERENCE_ISSUES=0

# Whether signing key was found
SIGNING_KEY_FOUND=false

SIGNING_PUB_PATH=""

# Principal (email) written to allowed_signers — used for the signing smoke test
SIGNING_PRINCIPAL=""

# OpenSSH client version and the version-appropriate name of the pubkey
# algorithm directive (PubkeyAcceptedAlgorithms >= 8.5, PubkeyAcceptedKeyTypes
# 7.0-8.4, empty = too old / unknown, directive skipped)
OPENSSH_VERSION=""
PUBKEY_ALGOS_DIRECTIVE="PubkeyAcceptedAlgorithms"

# Credential helper detected for this platform
DETECTED_CRED_HELPER=""

# Optional tool availability
HAS_YKMAN=false
HAS_FIDO2_TOKEN=false

# Set when a dependency is missing — suppresses trailing output so install
# instructions remain visible
MISSING_DEPENDENCY=false

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

die() {
    printf '%bError:%b %s\n' "$RED" "$RESET" "$1" >&2
    exit 1
}

# Strip inline comments and surrounding quotes from an SSH config value.
# Handles: value # comment, "value", 'value', "value" # comment
strip_ssh_value() {
    local val="$1"
    # Remove inline comment (not inside quotes): strip ' #...' from end
    # Be careful: only strip ' #' preceded by space (not part of path)
    val="$(printf '%s' "$val" | sed 's/[[:space:]]#.*$//')"
    # Remove surrounding double quotes
    val="${val#\"}"
    val="${val%\"}"
    # Remove surrounding single quotes
    val="${val#\'}"
    val="${val%\'}"
    # Trim whitespace
    val="$(printf '%s' "$val" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    printf '%s' "$val"
}

# List SSH config files to scan: the main config plus one level of Include
# expansion (globs and ~ resolved; relative paths resolve to ~/.ssh/).
# Deeper nesting is not followed — audit_ssh_config warns when Includes exist.
ssh_config_files() {
    [ -f "$SSH_CONFIG" ] || return 0
    printf '%s\n' "$SSH_CONFIG"

    local inc_line
    while IFS= read -r inc_line; do
        inc_line="$(strip_ssh_value "$inc_line")"
        [ -z "$inc_line" ] && continue
        local IFS_SAVE="$IFS"
        IFS=' 	'
        local pattern f
        for pattern in $inc_line; do
            pattern="${pattern/#\~/$HOME}"
            case "$pattern" in
                /*) ;;
                *) pattern="${SSH_DIR}/${pattern}" ;;
            esac
            # shellcheck disable=SC2086 # Intentional: Include values may glob
            for f in $pattern; do
                if [ -f "$f" ]; then
                    printf '%s\n' "$f"
                fi
            done
        done
        IFS="$IFS_SAVE"
    done <<EOF
$(grep -i '^[[:space:]]*include[[:space:]=]' "$SSH_CONFIG" 2>/dev/null | sed 's/^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]=]*//')
EOF
}

# Print raw IdentityFile values from the main SSH config and one level of
# included files.
list_identity_files() {
    local cfg
    while IFS= read -r cfg; do
        [ -n "$cfg" ] || continue
        grep -i '^[[:space:]]*IdentityFile[[:space:]=]' "$cfg" 2>/dev/null | \
            sed 's/^[[:space:]]*[Ii][Dd][Ee][Nn][Tt][Ii][Tt][Yy][Ff][Ii][Ll][Ee][[:space:]=]*//' || true
    done <<EOF
$(ssh_config_files)
EOF
}

# Set the tier attributed to subsequent print_warn/print_miss calls.
set_tier() {
    AUDIT_TIER="$1"
}

count_tier_issue() {
    case "$AUDIT_TIER" in
        security)   TIER_SECURITY_ISSUES=$((TIER_SECURITY_ISSUES + 1)) ;;
        hygiene)    TIER_HYGIENE_ISSUES=$((TIER_HYGIENE_ISSUES + 1)) ;;
        preference) TIER_PREFERENCE_ISSUES=$((TIER_PREFERENCE_ISSUES + 1)) ;;
    esac
}

print_ok() {
    printf '%b[OK]%b   %s\n' "$GREEN" "$RESET" "$1" >&2
    AUDIT_OK=$((AUDIT_OK + 1))
}

print_warn() {
    printf '%b[WARN]%b %s\n' "$YELLOW" "$RESET" "$1" >&2
    AUDIT_WARN=$((AUDIT_WARN + 1))
    count_tier_issue
}

print_miss() {
    printf '%b[MISS]%b %s\n' "$RED" "$RESET" "$1" >&2
    AUDIT_MISS=$((AUDIT_MISS + 1))
    count_tier_issue
}

# True if the file's first line looks like an SSH *public* key. Guards against
# private key material ending up in allowed_signers or git config.
is_public_key_file() {
    local f="$1"
    [ -f "$f" ] || return 1
    local first
    first="$(head -1 "$f" 2>/dev/null || true)"
    case "$first" in
        ssh-ed25519\ *|ssh-rsa\ *|ssh-dss\ *|ecdsa-sha2-*|sk-ssh-ed25519*|sk-ecdsa-sha2*)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

print_info() {
    printf '%b[INFO]%b %s\n' "$BLUE" "$RESET" "$1" >&2
}

print_header() {
    printf '\n%b── %s ──%b\n' "$BOLD" "$1" "$RESET" >&2
}

prompt_yn() {
    local prompt="$1"
    local default="${2:-y}"

    if [ "$AUTO_YES" = true ]; then
        return 0
    fi

    local yn_hint
    if [ "$default" = "y" ]; then
        yn_hint="[Y/n]"
    else
        yn_hint="[y/N]"
    fi

    local answer
    printf '%s %s ' "$prompt" "$yn_hint" >&2
    read -r answer </dev/tty || answer=""

    case "$answer" in
        [Yy]*) return 0 ;;
        [Nn]*) return 1 ;;
        "")
            if [ "$default" = "y" ]; then
                return 0
            else
                return 1
            fi
            ;;
        *) return 1 ;;
    esac
}

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -y|--yes)
                AUTO_YES=true
                shift
                ;;
            --audit)
                AUDIT_ONLY=true
                shift
                ;;
            --reset-signing)
                RESET_SIGNING=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            --version)
                printf 'git-harden.sh %s\n' "$VERSION"
                exit 0
                ;;
            *)
                die "Unknown option: $1. Use --help for usage."
                ;;
        esac
    done
}

usage() {
    cat >&2 <<'EOF'
Usage: git-harden.sh [OPTIONS]

Audit and harden your global git configuration.

Options:
  --audit           Run audit only (no changes), exit 0 if no security issues,
                    2 if security-tier issues found (hygiene/preference issues
                    are reported but do not affect the exit code)
  -y, --yes         Auto-apply all recommended settings (no prompts).
                    Never deletes files or keys.
  --reset-signing   Remove signing key config and optionally delete dedicated
                    signing key files (interactive only — never deletes in -y)
  --help, -h        Show this help message
  --version         Show version

Exit codes:
  0  No security issues, or changes successfully applied
  1  Error (missing dependencies, etc.)
  2  Audit found security-tier issues (--audit mode only)
EOF
}

# ------------------------------------------------------------------------------
# Platform detection
# ------------------------------------------------------------------------------

detect_platform() {
    local uname_out
    uname_out="$(uname -s)"
    case "$uname_out" in
        Darwin*) PLATFORM="macos" ;;
        Linux*)  PLATFORM="linux" ;;
        *)       die "Unsupported platform: $uname_out" ;;
    esac
}

# Compare version strings: returns 0 if $1 >= $2
version_gte() {
    local IFS_SAVE="$IFS"
    IFS='.'
    # shellcheck disable=SC2086
    set -- $1 $2
    IFS="$IFS_SAVE"
    # Force base-10 interpretation to avoid octal issues with leading zeros
    local a1=$((10#${1:-0})) a2=$((10#${2:-0})) a3=$((10#${3:-0}))
    local b1=$((10#${4:-0})) b2=$((10#${5:-0})) b3=$((10#${6:-0}))

    if [ "$a1" -gt "$b1" ]; then return 0; fi
    if [ "$a1" -lt "$b1" ]; then return 1; fi
    if [ "$a2" -gt "$b2" ]; then return 0; fi
    if [ "$a2" -lt "$b2" ]; then return 1; fi
    if [ "$a3" -ge "$b3" ]; then return 0; fi
    return 1
}

check_dependencies() {
    # git required
    if ! command -v git >/dev/null 2>&1; then
        die "git is not installed"
    fi

    local git_version
    git_version="$(git --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    if [ -z "$git_version" ]; then
        die "Could not parse git version from: $(git --version)"
    fi
    if ! version_gte "$git_version" "2.34.0"; then
        die "git >= 2.34.0 required (found $git_version)"
    fi

    # ssh-keygen required
    if ! command -v ssh-keygen >/dev/null 2>&1; then
        die "ssh-keygen is not installed"
    fi

    detect_openssh_version

    # Optional: ykman
    if command -v ykman >/dev/null 2>&1; then
        HAS_YKMAN=true
    fi

    # Optional: fido2-token
    if command -v fido2-token >/dev/null 2>&1; then
        HAS_FIDO2_TOKEN=true
    fi

    # Detect credential helper
    detect_credential_helper
}

# Parse the OpenSSH client version and pick the version-appropriate name for
# the pubkey algorithm directive. An unknown option in ~/.ssh/config makes
# EVERY ssh invocation fail ("Bad configuration option"), so getting the name
# wrong would break all SSH-based git operations.
detect_openssh_version() {
    if ! command -v ssh >/dev/null 2>&1; then
        PUBKEY_ALGOS_DIRECTIVE=""
        print_warn "ssh client not found — skipping SSH algorithm restrictions"
        return
    fi

    local ver_out major minor
    ver_out="$(ssh -V 2>&1 || true)"
    if [[ "$ver_out" =~ OpenSSH_([0-9]+)\.([0-9]+) ]]; then
        major="${BASH_REMATCH[1]}"
        minor="${BASH_REMATCH[2]}"
    else
        # Unknown client (e.g. a non-OpenSSH ssh) — don't risk writing an
        # option it may not understand
        PUBKEY_ALGOS_DIRECTIVE=""
        print_warn "Could not parse OpenSSH version ($ver_out) — skipping SSH algorithm restrictions"
        return
    fi

    OPENSSH_VERSION="${major}.${minor}"
    if (( major > 8 )) || { (( major == 8 )) && (( minor >= 5 )); }; then
        PUBKEY_ALGOS_DIRECTIVE="PubkeyAcceptedAlgorithms"
    elif (( major >= 7 )); then
        # Same option, pre-8.5 spelling
        PUBKEY_ALGOS_DIRECTIVE="PubkeyAcceptedKeyTypes"
    else
        PUBKEY_ALGOS_DIRECTIVE=""
        print_warn "OpenSSH ${OPENSSH_VERSION} predates pubkey algorithm restrictions — directive skipped"
    fi
}

# Check if a credential.helper value corresponds to a keychain-backed store.
# Returns 0 (true) if the helper stores credentials in the OS keychain.
is_keychain_credential_helper() {
    local helper="$1"
    case "$helper" in
        osxkeychain|manager|manager-core) return 0 ;;
        *git-credential-libsecret*)       return 0 ;;
        *git-credential-gnome-keyring*)   return 0 ;;
        *)                                return 1 ;;
    esac
}

detect_credential_helper() {
    # Git Credential Manager (GCM) — cross-platform, preferred when available
    if command -v git-credential-manager >/dev/null 2>&1; then
        DETECTED_CRED_HELPER="manager"
        return
    fi

    case "$PLATFORM" in
        macos)
            DETECTED_CRED_HELPER="osxkeychain"
            ;;
        linux)
            # Try libsecret (GNOME Keyring / KDE Wallet / any Secret Service provider)
            local libsecret_path=""
            for path in \
                /usr/lib/git-core/git-credential-libsecret \
                /usr/libexec/git-core/git-credential-libsecret \
                /usr/lib/git/git-credential-libsecret; do
                if [ -x "$path" ]; then
                    libsecret_path="$path"
                    break
                fi
            done

            if [ -n "$libsecret_path" ]; then
                DETECTED_CRED_HELPER="$libsecret_path"
                return
            fi

            # Fallback: in-memory cache (not persistent across reboots)
            DETECTED_CRED_HELPER="cache --timeout=3600"
            print_info "No keychain-backed credential helper found; falling back to in-memory cache (1h TTL)"
            credential_install_hint
            ;;
    esac
}

# Print distro-specific install hints for keychain credential storage.
credential_install_hint() {
    local distro_id=""
    if [[ -f /etc/os-release ]]; then
        distro_id="$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')"
    fi

    printf '  %bTo store credentials in the OS keychain, install one of:%b\n' "$YELLOW" "$RESET" >&2
    case "$distro_id" in
        ubuntu|debian|pop|linuxmint)
            printf '    • libsecret:  sudo apt install libsecret-1-dev git make && cd /usr/share/doc/git/contrib/credential/libsecret && sudo make\n' >&2
            printf '    • GCM:        https://github.com/git-ecosystem/git-credential-manager/releases\n' >&2
            ;;
        fedora|rhel|centos|rocky|alma)
            printf '    • libsecret:  sudo dnf install git-credential-libsecret\n' >&2
            printf '    • GCM:        https://github.com/git-ecosystem/git-credential-manager/releases\n' >&2
            ;;
        arch|manjaro|endeavouros)
            printf '    • libsecret:  sudo pacman -S libsecret\n' >&2
            printf '    • GCM:        https://github.com/git-ecosystem/git-credential-manager/releases\n' >&2
            ;;
        opensuse*|suse*)
            printf '    • libsecret:  sudo zypper install git-credential-libsecret\n' >&2
            printf '    • GCM:        https://github.com/git-ecosystem/git-credential-manager/releases\n' >&2
            ;;
        alpine)
            printf '    • GCM:        https://github.com/git-ecosystem/git-credential-manager/releases\n' >&2
            ;;
        *)
            printf '    • libsecret:  install git-credential-libsecret via your package manager\n' >&2
            printf '    • GCM:        https://github.com/git-ecosystem/git-credential-manager/releases\n' >&2
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Audit functions
# ------------------------------------------------------------------------------

# Check a single git config key against expected value.
# Returns: prints status, updates counters.
audit_git_setting() {
    local key="$1"
    local expected="$2"
    local label="${3:-$key}"

    local current
    current="$(git config --global --get "$key" 2>/dev/null || true)"

    if [ -z "$current" ]; then
        print_miss "$label (expected: $expected)"
    elif [ "$current" = "$expected" ]; then
        print_ok "$label = $current"
    else
        print_warn "$label = $current (expected: $expected)"
    fi
}

audit_git_config() {
    print_header "Identity"
    set_tier hygiene
    audit_git_setting "user.useConfigOnly" "true"

    # Warn if useConfigOnly would lock out commits (no global identity)
    local has_name has_email
    has_name="$(git config --global --get user.name 2>/dev/null || true)"
    has_email="$(git config --global --get user.email 2>/dev/null || true)"
    if [[ -z "$has_name" || -z "$has_email" ]]; then
        print_warn "user.name/user.email not set globally — useConfigOnly=true will block commits outside configured repos"
    fi

    print_header "Object Integrity"
    set_tier security
    audit_git_setting "transfer.fsckObjects" "true"
    audit_git_setting "fetch.fsckObjects" "true"
    audit_git_setting "receive.fsckObjects" "true"
    audit_git_setting "transfer.bundleURI" "false"
    set_tier hygiene
    audit_git_setting "fetch.prune" "true"
    set_tier security

    print_header "Protocol Restrictions"
    audit_git_setting "protocol.version" "2"
    audit_git_setting "protocol.allow" "never"
    audit_git_setting "protocol.https.allow" "always"
    audit_git_setting "protocol.ssh.allow" "always"
    audit_git_setting "protocol.file.allow" "user"
    audit_git_setting "protocol.git.allow" "never"
    audit_git_setting "protocol.ext.allow" "never"

    print_header "Filesystem Protection"
    audit_git_setting "core.protectNTFS" "true"
    audit_git_setting "core.protectHFS" "true"
    audit_git_setting "core.fsmonitor" "false"
    audit_git_setting "core.symlinks" "false"

    print_header "Hook Control"
    # shellcheck disable=SC2088 # Intentional: git config stores literal ~
    audit_git_setting "core.hooksPath" "~/.config/git/hooks"

    print_header "Repository Safety"
    audit_git_setting "safe.bareRepository" "explicit"
    audit_git_setting "submodule.recurse" "false"

    # Detect dangerous safe.directory = * wildcard (CVE-2022-24765)
    local safe_dirs
    safe_dirs="$(git config --global --get-all safe.directory 2>/dev/null || true)"
    if printf '%s\n' "$safe_dirs" | grep -qx '\*'; then
        print_warn "safe.directory = * disables ownership checks (CVE-2022-24765). Remove this setting."
    fi

    print_header "Pull/Merge Hardening"
    set_tier hygiene
    audit_git_setting "pull.ff" "only"
    audit_git_setting "merge.ff" "only"

    # AC-15: warn if pull.rebase is set (conflicts with pull.ff=only)
    local pull_rebase
    pull_rebase="$(git config --global --get pull.rebase 2>/dev/null || true)"
    if [ -n "$pull_rebase" ]; then
        print_warn "pull.rebase = $pull_rebase (conflicts with pull.ff=only — consider unsetting)"
    fi

    print_header "Transport Security"
    set_tier security
    # url.<base>.insteadOf needs special handling
    local instead_of
    instead_of="$(git config --global --get 'url.https://.insteadOf' 2>/dev/null || true)"
    if [ -z "$instead_of" ]; then
        print_miss "url.\"https://\".insteadOf (expected: http://)"
    elif [ "$instead_of" = "http://" ]; then
        print_ok "url.\"https://\".insteadOf = http://"
    else
        print_warn "url.\"https://\".insteadOf = $instead_of (expected: http://)"
    fi

    # http.sslVerify: git's default is already true — unset is NOT the same
    # as overridden. Only flag an explicit insecure override.
    local ssl_verify
    ssl_verify="$(git config --global --get http.sslVerify 2>/dev/null || true)"
    if [ -z "$ssl_verify" ]; then
        print_ok "http.sslVerify unset (git default: true — not overridden)"
    elif [ "$ssl_verify" = "true" ]; then
        print_ok "http.sslVerify = true"
    else
        print_warn "http.sslVerify = $ssl_verify (MITM risk — remove this override)"
    fi

    print_header "Credential Storage"
    local cred_current
    cred_current="$(git config --global --get credential.helper 2>/dev/null || true)"
    if [ -z "$cred_current" ]; then
        set_tier hygiene
        print_miss "credential.helper not set (credentials won't be cached)"
        set_tier security
    elif [ "$cred_current" = "store" ]; then
        print_warn "credential.helper = store (INSECURE: stores passwords in plaintext ~/.git-credentials)"
    elif is_keychain_credential_helper "$cred_current"; then
        print_ok "credential.helper = $cred_current (keychain-backed)"
    elif [ "$cred_current" = "$DETECTED_CRED_HELPER" ]; then
        print_ok "credential.helper = $cred_current"
    else
        print_warn "credential.helper = $cred_current (not a known keychain-backed helper)"
    fi

    print_header "Defaults"
    set_tier preference
    audit_git_setting "init.defaultBranch" "main"

    print_header "Forensic Readiness"
    set_tier hygiene
    audit_git_setting "gc.reflogExpire" "180.days"
    audit_git_setting "gc.reflogExpireUnreachable" "90.days"

    print_header "Visibility"
    set_tier preference
    audit_git_setting "log.showSignature" "true"
    set_tier security
}

audit_precommit_hook() {
    print_header "Pre-commit Hook"

    local hook_path="${HOOKS_DIR}/pre-commit"

    if [ ! -f "$hook_path" ]; then
        print_miss "No pre-commit hook at $hook_path"
        return
    fi

    if [ ! -x "$hook_path" ]; then
        print_warn "Pre-commit hook exists but is not executable: $hook_path"
        return
    fi

    if grep -q 'gitleaks' "$hook_path" 2>/dev/null; then
        if grep -q 'git-harden.sh' "$hook_path" 2>/dev/null && \
           ! grep -q 'local_hook' "$hook_path" 2>/dev/null; then
            print_warn "Pre-commit hook predates repo-local dispatch — re-run without --audit to upgrade"
        else
            print_ok "Pre-commit hook with gitleaks at $hook_path"
        fi
    else
        print_warn "Pre-commit hook exists but does not reference gitleaks (user-managed)"
    fi

    # If hooks are globally redirected, repo-local hooks only keep working
    # via dispatch stubs
    local hooks_path_cfg
    hooks_path_cfg="$(git config --global --get core.hooksPath 2>/dev/null || true)"
    if [ -n "$hooks_path_cfg" ]; then
        local missing=0 name
        for name in "${DISPATCH_HOOK_NAMES[@]}"; do
            [ -f "${HOOKS_DIR}/${name}" ] || missing=$((missing + 1))
        done
        if (( missing > 0 )); then
            set_tier hygiene
            print_warn "core.hooksPath is set but ${missing} dispatch stub(s) are missing — repo-local hooks (husky, lefthook, pre-commit framework) will not run"
            set_tier security
        else
            print_ok "Dispatch stubs present for ${#DISPATCH_HOOK_NAMES[@]} hook types (repo-local hooks keep working)"
        fi
    fi
}

audit_global_gitignore() {
    print_header "Global Gitignore"

    local excludes_file
    excludes_file="$(git config --global --get core.excludesFile 2>/dev/null || true)"

    if [ -z "$excludes_file" ]; then
        print_miss "core.excludesFile (no global gitignore configured)"
        return
    fi

    # Expand tilde
    local expanded_path
    expanded_path="${excludes_file/#\~/$HOME}"

    if [ ! -f "$expanded_path" ]; then
        print_warn "core.excludesFile = $excludes_file (file does not exist)"
        return
    fi

    # Check for key security patterns
    local has_security_patterns=false
    if grep -q '\.env' "$expanded_path" 2>/dev/null && \
       grep -q '\*\.pem' "$expanded_path" 2>/dev/null; then
        has_security_patterns=true
    fi

    if [ "$has_security_patterns" = true ]; then
        print_ok "core.excludesFile = $excludes_file (contains security patterns)"
    else
        print_warn "core.excludesFile = $excludes_file (lacks secret patterns: .env, *.pem, *.key — consider adding them)"
    fi
}

audit_credential_hygiene() {
    print_header "Credential Hygiene"

    # shellcheck disable=SC2088 # Intentional: ~ used as display text
    # ~/.git-credentials — plaintext git passwords
    if [ -f "${HOME}/.git-credentials" ]; then
        print_warn "~/.git-credentials exists (plaintext git credentials — migrate to credential helper and delete this file)"
    fi

    # shellcheck disable=SC2088 # Intentional: ~ used as display text
    # ~/.netrc — plaintext network credentials
    if [ -f "${HOME}/.netrc" ]; then
        print_warn "~/.netrc exists (plaintext network credentials — may contain git hosting tokens)"
    fi

    # ~/.npmrc — check for actual auth tokens
    if [ -f "${HOME}/.npmrc" ]; then
        if grep -qE '_authToken=.+' "${HOME}/.npmrc" 2>/dev/null; then
            # shellcheck disable=SC2088 # Intentional: ~ used as display text
            print_warn "~/.npmrc contains auth token (plaintext npm registry token — use env vars instead)"
        fi
    fi

    # ~/.pypirc — check for password field
    if [ -f "${HOME}/.pypirc" ]; then
        if grep -qE '^[[:space:]]*password' "${HOME}/.pypirc" 2>/dev/null; then
            # shellcheck disable=SC2088 # Intentional: ~ used as display text
            print_warn "~/.pypirc contains password (plaintext PyPI credentials — use keyring or token-based auth)"
        fi
    fi
}

audit_ssh_key_hygiene() {
    print_header "SSH Key Hygiene"

    local pub_files=()
    local seen_files=""

    # Collect ~/.ssh/*.pub files
    local f
    for f in "${SSH_DIR}"/*.pub; do
        [ -f "$f" ] || continue
        pub_files+=("$f")
        seen_files="${seen_files}|${f}"
    done

    # Also collect keys from IdentityFile directives in ~/.ssh/config and
    # one level of Include-d files
    local identity_path
    while IFS= read -r identity_path; do
        identity_path="$(strip_ssh_value "$identity_path")"
        [ -z "$identity_path" ] && continue
        identity_path="${identity_path/#\~/$HOME}"
        local pub_path="${identity_path}.pub"
        if [ -f "$pub_path" ]; then
            # Skip if already seen
            case "$seen_files" in
                *"|${pub_path}"*) continue ;;
            esac
            pub_files+=("$pub_path")
            seen_files="${seen_files}|${pub_path}"
        fi
    done <<EOF
$(list_identity_files)
EOF

    if [ ${#pub_files[@]} -eq 0 ]; then
        print_info "No SSH public keys found"
        return
    fi

    local key_type bits label
    for f in "${pub_files[@]}"; do
        key_type="$(awk '{print $1}' "$f" 2>/dev/null || true)"
        label="$(basename "$f")"

        case "$key_type" in
            ssh-ed25519)
                print_ok "SSH key $label (ed25519)"
                ;;
            sk-ssh-ed25519@openssh.com|sk-ssh-ed25519*)
                print_ok "SSH key $label (ed25519-sk, hardware-backed)"
                ;;
            sk-ecdsa-sha2-nistp256@openssh.com|sk-ecdsa-sha2*)
                print_ok "SSH key $label (ecdsa-sk, hardware-backed)"
                ;;
            ssh-rsa)
                bits="$(ssh-keygen -l -f "$f" 2>/dev/null | awk '{print $1}' || true)"
                if [ -n "$bits" ] && [ "$bits" -lt 2048 ] 2>/dev/null; then
                    print_warn "SSH key $label (RSA ${bits}-bit — weak, migrate to ed25519 immediately)"
                else
                    print_warn "SSH key $label (RSA ${bits:-?}-bit — consider migrating to ed25519)"
                fi
                ;;
            ssh-dss)
                print_warn "SSH key $label (DSA — deprecated, migrate to ed25519)"
                ;;
            ecdsa-sha2-*)
                print_warn "SSH key $label (ECDSA — consider migrating to ed25519)"
                ;;
            *)
                print_info "SSH key $label (unknown type: $key_type)"
                ;;
        esac
    done
}

audit_signing() {
    print_header "Signing Configuration"

    audit_git_setting "gpg.format" "ssh"
    # shellcheck disable=SC2088 # Intentional: git config stores literal ~
    audit_git_setting "gpg.ssh.allowedSignersFile" "~/.config/git/allowed_signers"

    # Check signing key
    local signing_key
    signing_key="$(git config --global --get user.signingkey 2>/dev/null || true)"
    if [ -z "$signing_key" ]; then
        print_miss "user.signingkey (no signing key configured)"
    else
        # Verify the key file exists
        local expanded_key
        expanded_key="${signing_key/#\~/$HOME}"
        if [ -f "$expanded_key" ]; then
            print_ok "user.signingkey = $signing_key"
        else
            # Key might be an inline key (starts with ssh-)
            case "$signing_key" in
                ssh-*|ecdsa-*|sk-*)
                    print_ok "user.signingkey = (inline key)"
                    ;;
                *)
                    print_warn "user.signingkey = $signing_key (file not found)"
                    ;;
            esac
        fi
    fi

    audit_git_setting "commit.gpgsign" "true"
    audit_git_setting "tag.gpgsign" "true"
    audit_git_setting "tag.forceSignAnnotated" "true"
}

audit_ssh_directive() {
    local directive="$1"
    local expected="$2"

    # Only values in global scope count: top-level (before any Host/Match
    # block) or inside a "Host *" block. A directive buried in a
    # host-specific block does NOT apply globally.
    local current
    current="$(get_ssh_directive_value "$directive")"

    if [ -z "$current" ]; then
        if grep -qi "^[[:space:]]*${directive}[[:space:]=]" "$SSH_CONFIG" 2>/dev/null; then
            print_warn "SSH: $directive set only in host-specific blocks — no global default (expected: $expected)"
        else
            print_miss "SSH: $directive (expected: $expected)"
        fi
    elif [ "$current" = "$expected" ]; then
        print_ok "SSH: $directive = $current"
    else
        print_warn "SSH: $directive = $current (expected: $expected)"
    fi
}

audit_ssh_config() {
    print_header "SSH Configuration"

    if [ ! -f "$SSH_CONFIG" ]; then
        set_tier security
        print_miss "$SSH_CONFIG does not exist"
        return
    fi

    if grep -qiE '^[[:space:]]*include[[:space:]=]' "$SSH_CONFIG" 2>/dev/null; then
        print_info "SSH config uses Include — directives inside included files are not audited or modified (key files in them are scanned)"
    fi

    set_tier security
    audit_ssh_directive "StrictHostKeyChecking" "accept-new"
    set_tier hygiene
    audit_ssh_directive "HashKnownHosts" "yes"
    set_tier security
    audit_ssh_directive "IdentitiesOnly" "yes"
    set_tier hygiene
    audit_ssh_directive "AddKeysToAgent" "yes"
    set_tier security
    if [ -n "$PUBKEY_ALGOS_DIRECTIVE" ]; then
        audit_ssh_directive "$PUBKEY_ALGOS_DIRECTIVE" "$PUBKEY_ALGO_LIST"
    fi
}

print_audit_report() {
    print_header "Audit Summary"
    printf '%b  %d OK  /  %d WARN  /  %d MISS%b\n' \
        "$BOLD" "$AUDIT_OK" "$AUDIT_WARN" "$AUDIT_MISS" "$RESET" >&2
    printf '  by tier:  %bsecurity: %d%b  /  hygiene: %d  /  preference: %d\n' \
        "$( (( TIER_SECURITY_ISSUES > 0 )) && printf '%s' "$RED" )" \
        "$TIER_SECURITY_ISSUES" "$RESET" \
        "$TIER_HYGIENE_ISSUES" "$TIER_PREFERENCE_ISSUES" >&2

    if [ $((AUDIT_WARN + AUDIT_MISS)) -gt 0 ]; then
        return 2
    fi
    return 0
}

# ------------------------------------------------------------------------------
# Apply functions
# ------------------------------------------------------------------------------

backup_git_config() {
    local config_file="${HOME}/.gitconfig"
    local xdg_config="${HOME}/.config/git/config"

    mkdir -p "$BACKUP_DIR"

    local timestamp
    timestamp="$(date +%Y%m%d-%H%M%S)"
    local backup_file="${BACKUP_DIR}/pre-harden-backup-${timestamp}.txt"

    # The config dump can contain secrets (http.extraHeader auth, tokens in
    # insteadOf URLs) — restrict permissions before writing any content
    touch "$backup_file"
    chmod 600 "$backup_file"

    {
        echo "# git-harden.sh backup — $timestamp"
        echo "# Global git config snapshot"
        echo ""
        if [ -f "$config_file" ]; then
            echo "## ~/.gitconfig"
            cat "$config_file"
            echo ""
        fi
        if [ -f "$xdg_config" ]; then
            echo "## ~/.config/git/config"
            cat "$xdg_config"
            echo ""
        fi
        echo "## git config --global --list"
        git config --global --list 2>/dev/null || echo "(no global config)"
    } > "$backup_file"

    print_info "Config backed up to $backup_file"
}

# Check if a git config setting needs changing. Returns 0 if it does.
setting_needs_change() {
    local key="$1"
    local value="$2"
    local current
    current="$(git config --global --get "$key" 2>/dev/null || true)"
    [ "$current" != "$value" ]
}

# Apply a group of git config settings with a single prompt.
# Arguments: group_name description key1 value1 explanation1 key2 value2 explanation2 ...
apply_setting_group() {
    local group_name="$1"
    local description="$2"
    shift 2

    # Collect pending changes (settings that need updating)
    local pending_keys=()
    local pending_vals=()
    local pending_explanations=()

    while [ $# -ge 3 ]; do
        local key="$1" value="$2" explanation="$3"
        shift 3
        if setting_needs_change "$key" "$value"; then
            pending_keys+=("$key")
            pending_vals+=("$value")
            pending_explanations+=("$explanation")
        fi
    done

    local count="${#pending_keys[@]}"

    # Nothing to do
    if [ "$count" -eq 0 ]; then
        return 0
    fi

    print_header "$group_name"
    printf '  %s\n\n' "$description" >&2

    # Show what will change
    local i
    for ((i = 0; i < count; i++)); do
        printf '    %-40s %s\n' "${pending_keys[$i]} = ${pending_vals[$i]}" "# ${pending_explanations[$i]}" >&2
    done
    printf '\n' >&2

    if prompt_yn "Apply these ${count} settings?"; then
        for ((i = 0; i < count; i++)); do
            git config --global "${pending_keys[$i]}" "${pending_vals[$i]}"
        done
        print_info "Applied ${count} settings"
    fi
}

apply_git_config() {

    # --- Group 1: Object Integrity ---
    apply_setting_group "Object Integrity" \
        "Validate all transferred git objects to catch corruption or malicious payloads." \
        "transfer.fsckObjects"  "true"       "Verify objects on transfer" \
        "fetch.fsckObjects"     "true"       "Verify objects on fetch" \
        "receive.fsckObjects"   "true"       "Verify objects on receive" \
        "transfer.bundleURI"    "false"      "Disable bundle URI fetching (attack surface)" \
        "fetch.prune"           "true"       "Auto-remove stale remote tracking refs"

    # --- Group 2: Protocol Restrictions ---
    apply_setting_group "Protocol Restrictions" \
        "Default-deny policy: only HTTPS and SSH allowed." \
        "protocol.version"      "2"          "Use wire protocol v2 (faster, smaller surface)" \
        "protocol.allow"        "never"      "Default-deny all protocols" \
        "protocol.https.allow"  "always"     "Allow HTTPS" \
        "protocol.ssh.allow"    "always"     "Allow SSH" \
        "protocol.file.allow"   "user"       "Allow local file protocol (user-initiated only)" \
        "protocol.git.allow"    "never"      "Block unencrypted git:// protocol" \
        "protocol.ext.allow"    "never"      "Block ext:// (arbitrary command execution)"

    # --- Group 3: Filesystem & Repository Safety ---
    # shellcheck disable=SC2088 # Intentional: git config stores literal ~
    local hooks_path_val="~/.config/git/hooks"

    apply_setting_group "Filesystem & Repository Safety" \
        "Prevent path traversal, malicious hooks, and unsafe repo configurations." \
        "core.protectNTFS"      "true"              "Block NTFS 8.3 short-name attacks" \
        "core.protectHFS"       "true"              "Block HFS+ Unicode normalization attacks" \
        "core.fsmonitor"        "false"             "Disable filesystem monitor (attack surface)" \
        "safe.bareRepository"   "explicit"          "Require --git-dir for bare repos" \
        "submodule.recurse"     "false"             "Don't auto-recurse into submodules"

    # core.hooksPath: separate prompt — this overrides ALL per-repo hooks
    if setting_needs_change "core.hooksPath" "$hooks_path_val"; then
        print_header "Global Hooks Path"
        printf '  %bWarning:%b Setting core.hooksPath redirects ALL hook execution to a\n' "$YELLOW" "$RESET" >&2
        printf '  central directory, so per-repo hooks (.git/hooks/) no longer run directly.\n' >&2
        printf '  To keep frameworks like husky, lefthook, and pre-commit working, this\n' >&2
        printf '  script installs dispatch stubs there that forward every hook type to the\n' >&2
        printf '  repository'\''s own hooks (offered in the next step).\n\n' >&2
        printf '    core.hooksPath = %s\n\n' "$hooks_path_val" >&2
        if prompt_yn "Set core.hooksPath? (overrides per-repo hooks)"; then
            git config --global core.hooksPath "$hooks_path_val"
            print_info "Set core.hooksPath = $hooks_path_val"
        fi
    fi

    # core.symlinks: interactive-only (may break symlink-dependent workflows)
    if [ "$AUTO_YES" = false ]; then
        local current_symlinks
        current_symlinks="$(git config --global --get core.symlinks 2>/dev/null || true)"
        if [ "$current_symlinks" != "false" ]; then
            if prompt_yn "Disable symlinks (CVE-2024-32002)? May break Node.js monorepos, etc."; then
                git config --global core.symlinks false
                print_info "Set core.symlinks = false"
            fi
        fi
    fi

    # Remove dangerous safe.directory = * wildcard if present
    local safe_dirs
    safe_dirs="$(git config --global --get-all safe.directory 2>/dev/null || true)"
    if printf '%s\n' "$safe_dirs" | grep -qx '\*'; then
        if prompt_yn "Remove dangerous safe.directory = * (disables ownership checks, CVE-2022-24765)?"; then
            git config --global --unset 'safe.directory' '\*' 2>/dev/null || \
                git config --global --unset-all 'safe.directory' '\*' 2>/dev/null || true
            print_info "Removed safe.directory = *"
        fi
    fi

    mkdir -p "$HOOKS_DIR"

    # --- Group 4: Pull/Merge & Transport ---
    # url.https.insteadOf needs special handling — check first
    local instead_of
    instead_of="$(git config --global --get 'url.https://.insteadOf' 2>/dev/null || true)"

    apply_setting_group "Pull/Merge & Transport Security" \
        "Refuse non-fast-forward merges and force HTTPS." \
        "pull.ff"               "only"       "Reject non-fast-forward pulls" \
        "merge.ff"              "only"       "Reject non-fast-forward merges" \
        "http.sslVerify"        "true"       "Enforce TLS certificate validation"

    # url rewrite is separate (not a simple key=value)
    if [ "$instead_of" != "http://" ]; then
        if prompt_yn "Rewrite http:// URLs to https:// automatically?"; then
            git config --global 'url.https://.insteadOf' 'http://'
            print_info "Set url.\"https://\".insteadOf = http://"
        fi
    fi

    # pull.rebase conflicts with pull.ff=only — offer to unset
    local pull_rebase
    pull_rebase="$(git config --global --get pull.rebase 2>/dev/null || true)"
    if [[ -n "$pull_rebase" ]]; then
        printf '\n  %bpull.rebase = %s conflicts with pull.ff = only%b\n' "$YELLOW" "$pull_rebase" "$RESET" >&2
        printf '  With pull.ff=only, git already refuses non-fast-forward pulls.\n' >&2
        printf '  Having pull.rebase set alongside it causes confusing errors.\n\n' >&2
        if prompt_yn "Unset pull.rebase?"; then
            git config --global --unset pull.rebase
            print_info "Unset pull.rebase"
        fi
    fi

    # --- Group 5: Credential, Identity & Defaults ---
    local cred_current
    cred_current="$(git config --global --get credential.helper 2>/dev/null || true)"

    apply_setting_group "Defaults & Visibility" \
        "Sensible defaults for new repositories and log output." \
        "init.defaultBranch"    "main"       "Default branch name for new repos" \
        "log.showSignature"     "true"       "Show signature status in git log"

    # user.useConfigOnly needs a guard — it locks out commits without identity
    if setting_needs_change "user.useConfigOnly" "true"; then
        local has_name has_email
        has_name="$(git config --global --get user.name 2>/dev/null || true)"
        has_email="$(git config --global --get user.email 2>/dev/null || true)"
        if [[ -z "$has_name" || -z "$has_email" ]]; then
            print_header "Identity Guard"
            printf '  %buseConfigOnly=true blocks commits without user.name and user.email.%b\n' "$YELLOW" "$RESET" >&2
            printf '  You are missing: %s\n\n' \
                "$( [[ -z "$has_name" ]] && printf 'user.name '; [[ -z "$has_email" ]] && printf 'user.email' )" >&2
            if [[ -z "$has_name" ]]; then
                printf '  Enter your name (or press Enter to skip): ' >&2
                local input_name
                read -r input_name </dev/tty || input_name=""
                if [[ -n "$input_name" ]]; then
                    git config --global user.name "$input_name"
                    print_info "Set user.name = $input_name"
                    has_name="$input_name"
                fi
            fi
            if [[ -z "$has_email" ]]; then
                printf '  Enter your email (or press Enter to skip): ' >&2
                local input_email
                read -r input_email </dev/tty || input_email=""
                if [[ -n "$input_email" ]]; then
                    git config --global user.email "$input_email"
                    print_info "Set user.email = $input_email"
                    has_email="$input_email"
                fi
            fi
            if [[ -z "$has_name" || -z "$has_email" ]]; then
                print_warn "Skipping user.useConfigOnly — set user.name and user.email first to avoid being locked out"
            else
                git config --global user.useConfigOnly true
                print_info "Set user.useConfigOnly = true"
            fi
        else
            if prompt_yn "Set user.useConfigOnly = true? (block commits without explicit identity)"; then
                git config --global user.useConfigOnly true
                print_info "Set user.useConfigOnly = true"
            fi
        fi
    fi

    # Credential helper needs special logic — accept any keychain-backed helper
    if is_keychain_credential_helper "$cred_current" 2>/dev/null; then
        : # Already using a keychain-backed helper — leave it alone
    elif [ "$cred_current" != "$DETECTED_CRED_HELPER" ]; then
        local cred_prompt="Set credential.helper = $DETECTED_CRED_HELPER?"
        if [ "$cred_current" = "store" ]; then
            cred_prompt="Replace INSECURE credential.helper=store with $DETECTED_CRED_HELPER?"
        fi
        if prompt_yn "$cred_prompt"; then
            git config --global credential.helper "$DETECTED_CRED_HELPER"
            print_info "Set credential.helper = $DETECTED_CRED_HELPER"
        fi
    fi

    # --- Group 6: Forensic Readiness ---
    apply_setting_group "Forensic Readiness" \
        "Extend reflog retention for post-incident investigation." \
        "gc.reflogExpire"              "180.days"  "Keep reachable reflog 180 days (default: 90)" \
        "gc.reflogExpireUnreachable"   "90.days"   "Keep unreachable reflog 90 days (default: 30)"
}

# Write the combined gitleaks + repo-local-dispatch pre-commit hook.
write_precommit_hook() {
    local hook_path="$1"
    mkdir -p "$HOOKS_DIR"
    cat > "$hook_path" << 'HOOK_EOF'
#!/usr/bin/env bash
# Installed by git-harden.sh — global pre-commit: secret scan + dispatch.
# Runs gitleaks on the staged diff, then dispatches to the repository's own
# pre-commit hook (.git/hooks/pre-commit), which core.hooksPath would
# otherwise silently disable.
# To bypass the secret scan for a single commit: SKIP_GITLEAKS=1 git commit
set -o errexit
set -o nounset
set -o pipefail

if [ "${SKIP_GITLEAKS:-0}" = "1" ]; then
    :
elif command -v gitleaks >/dev/null 2>&1; then
    gitleaks protect --staged --redact --verbose
else
    printf 'git-harden pre-commit: gitleaks not installed — secret scan SKIPPED\n' >&2
    printf '  Install it: brew install gitleaks (macOS) or https://github.com/gitleaks/gitleaks\n' >&2
fi

# Dispatch to the repo-local hook so frameworks (husky, lefthook,
# pre-commit) keep working. Deliberately uses .git/hooks directly:
# `git rev-parse --git-path hooks` would resolve back to THIS directory.
git_dir="$(git rev-parse --git-dir 2>/dev/null)" || exit 0
local_hook="${git_dir}/hooks/pre-commit"
if [ -x "$local_hook" ]; then
    exec "$local_hook" "$@"
fi
exit 0
HOOK_EOF
    chmod +x "$hook_path"
    print_info "Installed gitleaks + dispatch pre-commit hook at $hook_path"
}

apply_precommit_hook() {
    print_header "Pre-commit Hook (gitleaks)"

    local hook_path="${HOOKS_DIR}/pre-commit"

    if [ -f "$hook_path" ]; then
        if grep -q 'gitleaks' "$hook_path" 2>/dev/null; then
            # Our pre-dispatch hook version silently disabled repo-local
            # hooks — offer the upgrade
            if grep -q 'git-harden.sh' "$hook_path" 2>/dev/null && \
               ! grep -q 'local_hook' "$hook_path" 2>/dev/null; then
                if prompt_yn "Upgrade git-harden pre-commit hook to also dispatch to repo-local hooks?"; then
                    write_precommit_hook "$hook_path"
                fi
            fi
            return
        fi
        print_info "Existing pre-commit hook found — not overwriting"
        return
    fi

    if ! command -v gitleaks >/dev/null 2>&1; then
        print_warn "gitleaks not found — install it for pre-commit secret scanning:"
        printf '    macOS:  brew install gitleaks\n' >&2
        printf '    Linux:  apt install gitleaks / dnf install gitleaks (or download from GitHub releases)\n' >&2
    fi

    if prompt_yn "Install gitleaks pre-commit hook at $hook_path?"; then
        write_precommit_hook "$hook_path"
    fi
}

# Install thin dispatch stubs for every client-side hook type so that
# redirecting core.hooksPath does not silently disable repo-local hooks
# (the stub forwards to .git/hooks/<name> when present and executable).
apply_dispatch_hooks() {
    # Only relevant when hooks are globally redirected to our directory
    local hooks_path_cfg
    hooks_path_cfg="$(git config --global --get core.hooksPath 2>/dev/null || true)"
    local expanded_cfg="${hooks_path_cfg/#\~/$HOME}"
    if [ "$expanded_cfg" != "$HOOKS_DIR" ]; then
        return 0
    fi

    local missing=() name
    for name in "${DISPATCH_HOOK_NAMES[@]}"; do
        if [ ! -f "${HOOKS_DIR}/${name}" ]; then
            missing+=("$name")
        fi
    done

    if [ ${#missing[@]} -eq 0 ]; then
        return 0
    fi

    print_header "Repo-local Hook Dispatch"
    printf '  core.hooksPath redirects ALL hooks to %s.\n' "$HOOKS_DIR" >&2
    printf '  Dispatch stubs forward each hook type to the repository'\''s own\n' >&2
    printf '  .git/hooks/ so frameworks like husky, lefthook and pre-commit\n' >&2
    printf '  keep working. Missing stubs: %d\n\n' "${#missing[@]}" >&2

    if ! prompt_yn "Install dispatch stubs for ${#missing[@]} hook type(s)?"; then
        print_warn "Without dispatch stubs, repo-local hooks will NOT run while core.hooksPath is set"
        return 0
    fi

    mkdir -p "$HOOKS_DIR"
    for name in "${missing[@]}"; do
        cat > "${HOOKS_DIR}/${name}" << 'DISPATCH_EOF'
#!/usr/bin/env bash
# Installed by git-harden.sh — dispatch stub.
# core.hooksPath redirects all hooks to this directory; this stub forwards
# to the repository's own hook so repo-local hooks keep working.
# Deliberately uses .git/hooks directly: `git rev-parse --git-path hooks`
# would resolve back to THIS directory and recurse.
set -o nounset
hook_name="$(basename "$0")"
git_dir="$(git rev-parse --git-dir 2>/dev/null)" || exit 0
local_hook="${git_dir}/hooks/${hook_name}"
if [ -x "$local_hook" ]; then
    exec "$local_hook" "$@"
fi
exit 0
DISPATCH_EOF
        chmod +x "${HOOKS_DIR}/${name}"
    done
    print_info "Installed ${#missing[@]} dispatch stub(s) in $HOOKS_DIR"
}

apply_global_gitignore() {
    print_header "Global Gitignore"

    local excludes_file
    excludes_file="$(git config --global --get core.excludesFile 2>/dev/null || true)"

    if [ -n "$excludes_file" ]; then
        local expanded_path
        expanded_path="${excludes_file/#\~/$HOME}"
        print_info "core.excludesFile already set to $excludes_file"
        if [ -f "$expanded_path" ]; then
            local has_security_patterns=false
            if grep -q '\.env' "$expanded_path" 2>/dev/null && \
               grep -q '\*\.pem' "$expanded_path" 2>/dev/null; then
                has_security_patterns=true
            fi
            if [ "$has_security_patterns" = false ]; then
                print_warn "Your global gitignore lacks secret patterns (.env, *.pem, *.key) — consider adding them"
            fi
        fi
        return
    fi

    if prompt_yn "Create global gitignore with security patterns at $GLOBAL_GITIGNORE?"; then
        mkdir -p "$(dirname "$GLOBAL_GITIGNORE")"
        cat > "$GLOBAL_GITIGNORE" << 'GITIGNORE_EOF'
# === Security: secrets & credentials ===
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.pfx
*.jks
credentials.json
service-account*.json
.git-credentials
.netrc
.npmrc
.pypirc

# === Security: Terraform state (contains secrets) ===
*.tfstate
*.tfstate.backup

# === OS artifacts ===
.DS_Store
Thumbs.db
Desktop.ini

# === IDE artifacts ===
.idea/
.vscode/
*.swp
*.swo
*~
GITIGNORE_EOF
        print_info "Created $GLOBAL_GITIGNORE"

        # shellcheck disable=SC2088 # Intentional: git config stores literal ~
        git config --global core.excludesFile "~/.config/git/ignore"
        print_info "Set core.excludesFile = ~/.config/git/ignore"
    fi
}

apply_signing_config() {
    print_header "Signing Configuration"

    # Always safe to set format and allowed signers
    if setting_needs_change "gpg.format" "ssh"; then
        git config --global gpg.format ssh
        print_info "Set gpg.format = ssh"
    fi
    # shellcheck disable=SC2088 # Intentional: git config stores literal ~
    local signers_path="~/.config/git/allowed_signers"
    if setting_needs_change "gpg.ssh.allowedSignersFile" "$signers_path"; then
        git config --global gpg.ssh.allowedSignersFile "$signers_path"
        print_info "Set gpg.ssh.allowedSignersFile = $signers_path"
    fi

    # Detect existing signing key
    detect_existing_keys

    if [ "$AUTO_YES" = true ]; then
        # In -y mode: only enable signing if key exists
        if [ "$SIGNING_KEY_FOUND" = true ] && [ -n "$SIGNING_PUB_PATH" ] && [ -f "$SIGNING_PUB_PATH" ]; then
            enable_signing "$SIGNING_PUB_PATH"
        else
            print_info "No SSH signing key found. Skipping commit.gpgsign and tag.gpgsign."
            print_info "Run git-harden.sh interactively (without -y) to set up signing."
        fi
    else
        # Interactive mode: run the wizard
        signing_wizard
    fi
}

detect_existing_keys() {
    SIGNING_KEY_FOUND=false
    
    SIGNING_PUB_PATH=""

    # Check if a signing key is already configured
    local configured_key
    configured_key="$(git config --global --get user.signingkey 2>/dev/null || true)"
    if [ -n "$configured_key" ]; then
        local expanded_key
        expanded_key="${configured_key/#\~/$HOME}"
        # git accepts a PRIVATE key path in user.signingkey — never treat one
        # as the public key (it would end up cat'ed into allowed_signers)
        if is_public_key_file "$expanded_key"; then
            SIGNING_KEY_FOUND=true
            SIGNING_PUB_PATH="$expanded_key"
            return
        fi
        if [ -f "$expanded_key" ] && is_public_key_file "${expanded_key}.pub"; then
            print_warn "user.signingkey points to a private key — using ${expanded_key}.pub instead"
            SIGNING_KEY_FOUND=true
            SIGNING_PUB_PATH="${expanded_key}.pub"
            return
        fi
        if [ -f "$expanded_key" ]; then
            print_warn "user.signingkey = $configured_key is not a public key file — ignoring it"
        fi
    fi

    # Check common ed25519 key locations (dedicated signing keys first, then general)
    local priv_path pub_path
    for key_type in id_ed25519_sk_signing id_ecdsa_sk_signing id_ed25519_signing id_ed25519_sk id_ed25519; do
        priv_path="${SSH_DIR}/${key_type}"
        pub_path="${priv_path}.pub"
        if [ -f "$pub_path" ]; then
            SIGNING_KEY_FOUND=true

            SIGNING_PUB_PATH="$pub_path"
            return
        fi
    done

    # Check IdentityFile directives in ~/.ssh/config (and one level of
    # Include-d files) for custom-named keys
    local identity_path
    while IFS= read -r identity_path; do
        # Strip inline comments and quotes
        identity_path="$(strip_ssh_value "$identity_path")"
        [ -z "$identity_path" ] && continue
        # Expand tilde safely
        identity_path="${identity_path/#\~/$HOME}"

        pub_path="${identity_path}.pub"
        if [ -f "$pub_path" ]; then
            # Only use ed25519, ed25519-sk, or ecdsa-sk keys for signing
            local key_type_str
            key_type_str="$(head -1 "$pub_path" 2>/dev/null || true)"
            case "$key_type_str" in
                ssh-ed25519*|sk-ssh-ed25519*|sk-ecdsa-sha2*)
                    SIGNING_KEY_FOUND=true

                    SIGNING_PUB_PATH="$pub_path"
                    return
                    ;;
            esac
        fi
    done <<EOF
$(list_identity_files)
EOF
}

detect_fido2_hardware() {
    # Check via ykman (cross-platform)
    if [ "$HAS_YKMAN" = true ]; then
        if ykman info >/dev/null 2>&1; then
            return 0
        fi
    fi
    # Check via fido2-token (Linux)
    if [ "$HAS_FIDO2_TOKEN" = true ]; then
        if fido2-token -L 2>/dev/null | grep -q .; then
            return 0
        fi
    fi
    # macOS: check IOKit USB registry for FIDO devices (works without ykman)
    if [ "$PLATFORM" = "macos" ]; then
        if ioreg -p IOUSB -l 2>/dev/null | grep -qi "fido\|yubikey\|security key\|titan"; then
            return 0
        fi
    fi
    # Linux: check hidraw report descriptors for the FIDO HID usage page (0xF1D0).
    # Bytes 06 d0 f1 at the start of the descriptor = HID usage page 0xF1D0.
    # This works for any FIDO key vendor (Yubico, SoloKeys, Google Titan, etc.).
    if [ "$PLATFORM" = "linux" ]; then
        local rdesc
        for rdesc in /sys/class/hidraw/hidraw*/device/report_descriptor; do
            [ -f "$rdesc" ] || continue
            if od -A n -t x1 -N 3 "$rdesc" 2>/dev/null | grep -qi '06 d0 f1'; then
                return 0
            fi
        done
    fi
    return 1
}

signing_wizard() {
    print_header "SSH Signing Setup Wizard"

    printf '\n  %bPrivacy note:%b Your signing key is public — it appears in every signed\n' "$YELLOW" "$RESET" >&2
    printf '  commit and on your GitHub/GitLab profile. Using the same key across\n' >&2
    printf '  personal and work accounts links those identities (OSINT risk). If\n' >&2
    printf '  identity separation matters, generate a dedicated key per context and\n' >&2
    printf '  use git'\''s includeIf to configure per-org signing keys.\n' >&2

    if [ "$SIGNING_KEY_FOUND" = true ]; then
        printf '\n  Found existing key: %s\n' "$SIGNING_PUB_PATH" >&2
        if prompt_yn "Use this key for git signing? (enables commit + tag signing)"; then
            enable_signing "$SIGNING_PUB_PATH"
            return
        fi
    fi

    # Offer key generation options
    printf '\n  Signing key options:\n' >&2
    printf '    1) Generate a new ed25519 SSH key (software)\n' >&2
    printf '    2) Generate a hardware-backed SSH key (FIDO2/U2F security key)\n' >&2
    printf '    s) Skip signing setup (e.g. in an agent container where humans sign at PR merge)\n' >&2

    local choice
    printf '\n  Choose [1/2/s]: ' >&2
    read -r choice </dev/tty || choice="s"

    case "$choice" in
        1)
            generate_ssh_key
            ;;
        2)
            generate_fido2_key
            ;;
        *)
            print_info "Skipping signing setup."
            return
            ;;
    esac

    if [ "$SIGNING_KEY_FOUND" = true ]; then
        if prompt_yn "Enable commit and tag signing with this key?"; then
            enable_signing "$SIGNING_PUB_PATH"
        fi
    fi
}

reset_signing() {
    print_header "Reset Signing Configuration"

    local signing_key
    signing_key="$(git config --global --get user.signingkey 2>/dev/null || true)"

    if [ -n "$signing_key" ]; then
        printf '  Current signing key: %s\n' "$signing_key" >&2

        # Remove git config entries
        git config --global --unset user.signingkey 2>/dev/null || true
        git config --global --unset commit.gpgsign 2>/dev/null || true
        git config --global --unset tag.gpgsign 2>/dev/null || true
        git config --global --unset tag.forceSignAnnotated 2>/dev/null || true
        print_info "Removed signing configuration from git config"

        # Remove allowed_signers entry if the key file exists
        local key_path="${signing_key/#\~/$HOME}"
        if [ -f "$key_path" ] && [ -f "$ALLOWED_SIGNERS_FILE" ]; then
            local pub_key
            pub_key="$(cat "$key_path")"
            local tmpfile
            tmpfile="$(mktemp -t git-harden-signers.XXXXXX)"
            grep -vF "$pub_key" "$ALLOWED_SIGNERS_FILE" > "$tmpfile" 2>/dev/null || true
            mv "$tmpfile" "$ALLOWED_SIGNERS_FILE"
            print_info "Removed key from $ALLOWED_SIGNERS_FILE"
        fi
    else
        print_info "No signing key in git config"
    fi

    # Collect key files eligible for removal. ONLY dedicated signing keys
    # (*_signing naming convention) are candidates — general-purpose keys like
    # id_ed25519 may be the user's SSH AUTHENTICATION key and deleting them
    # would lock the user out of every server that key authenticates to.
    local key_files=()
    local candidate
    local seen_paths=""

    # Include the configured key only when it is a dedicated signing key
    if [[ -n "$signing_key" ]]; then
        local configured_path="${signing_key/#\~/$HOME}"
        local configured_base
        configured_base="$(basename "$configured_path")"
        if [[ "$configured_base" == *_signing* ]]; then
            for candidate in "$configured_path" "${configured_path%.pub}"; do
                if [[ -f "$candidate" ]] && [[ "$seen_paths" != *"|${candidate}|"* ]]; then
                    key_files+=("$candidate")
                    seen_paths="${seen_paths}|${candidate}|"
                fi
            done
        elif [[ -f "$configured_path" ]]; then
            print_info "Configured key $signing_key is not a dedicated signing key (may be used for SSH authentication) — leaving its files in place"
        fi
    fi

    # Also check well-known dedicated signing key names
    for candidate in \
        "${SSH_DIR}/id_ed25519_sk_signing" "${SSH_DIR}/id_ed25519_sk_signing.pub" \
        "${SSH_DIR}/id_ecdsa_sk_signing"   "${SSH_DIR}/id_ecdsa_sk_signing.pub" \
        "${SSH_DIR}/id_ed25519_signing"    "${SSH_DIR}/id_ed25519_signing.pub"; do
        if [[ -f "$candidate" ]] && [[ "$seen_paths" != *"|${candidate}|"* ]]; then
            key_files+=("$candidate")
            seen_paths="${seen_paths}|${candidate}|"
        fi
    done

    if (( ${#key_files[@]} > 0 )); then
        local backup_suffix
        backup_suffix=".bak.$(date +%Y%m%dT%H%M%S)"

        printf '\n  Signing key files found:\n' >&2
        local kf
        for kf in "${key_files[@]}"; do
            printf '    %s\n' "$kf" >&2
        done

        # Deleting keys is irreversible — never do it without an explicit,
        # interactive yes (prompt_yn auto-accepts in -y mode, so guard first)
        if [ "$AUTO_YES" = true ]; then
            print_info "Key files left in place (-y mode never deletes keys). Re-run interactively to remove them."
        elif prompt_yn "Delete these key files? (irreversible)" "n"; then
            for kf in "${key_files[@]}"; do
                rm -f "$kf"
            done
            print_info "Key files deleted"
        elif prompt_yn "Rename them with a ${backup_suffix} suffix instead? (No = leave untouched)" "n"; then
            for kf in "${key_files[@]}"; do
                mv "$kf" "${kf}${backup_suffix}"
            done
            print_info "Key files renamed with suffix ${backup_suffix}"
        else
            print_info "Key files left untouched"
        fi
    else
        print_info "No dedicated signing key files found"
    fi
}

# Enable signing with a given public key path. Sets signingkey, gpgsign,
# and forceSignAnnotated in one step (no individual prompts).
enable_signing() {
    local pub_path="$1"
    if ! is_public_key_file "$pub_path"; then
        print_warn "$pub_path does not look like an SSH public key — not enabling signing"
        return
    fi
    git config --global user.signingkey "$pub_path"
    git config --global commit.gpgsign true
    git config --global tag.gpgsign true
    git config --global tag.forceSignAnnotated true
    print_info "Signing enabled: commits and tags will be signed with $pub_path"
    setup_allowed_signers
    verify_signing_setup "$pub_path"
}

# Smoke-test the signing setup: sign a test message and verify it against
# allowed_signers with the recorded principal. Catches the "Good signature
# but No principal matched" misconfiguration at setup time instead of in
# every future `git log`.
verify_signing_setup() {
    local pub_path="$1"
    local priv_path="${pub_path%.pub}"

    # Signing may require a hardware-key touch or a passphrase — never
    # attempt it in non-interactive mode
    if [ "$AUTO_YES" = true ]; then
        return 0
    fi
    if [ -z "$SIGNING_PRINCIPAL" ] || [ ! -f "$priv_path" ] || [ ! -f "$ALLOWED_SIGNERS_FILE" ]; then
        return 0
    fi
    if ! prompt_yn "Verify signing works now? (may require a key touch or passphrase)"; then
        return 0
    fi

    local tmpdir
    tmpdir="$(mktemp -d -t git-harden-verify.XXXXXX)"
    printf 'git-harden signing verification\n' > "${tmpdir}/msg"

    local verify_ok=false
    # Keep sign stderr visible — it carries the touch/passphrase prompts
    if ssh-keygen -Y sign -n git -f "$priv_path" "${tmpdir}/msg" >/dev/null && \
       ssh-keygen -Y verify -n git -f "$ALLOWED_SIGNERS_FILE" -I "$SIGNING_PRINCIPAL" \
           -s "${tmpdir}/msg.sig" < "${tmpdir}/msg" >/dev/null 2>&1; then
        verify_ok=true
    fi
    rm -rf "$tmpdir"

    if [ "$verify_ok" = true ]; then
        print_info "Signature round-trip verified: key signs and allowed_signers matches principal ${SIGNING_PRINCIPAL}"
    else
        print_warn "Signature verification failed — commits will be signed, but verification will show 'No principal matched'"
        printf '  Check that the email in %s matches the email on your commits\n' "$ALLOWED_SIGNERS_FILE" >&2
        printf '  (repos overriding user.email need their own allowed_signers entry).\n' >&2
    fi
}

generate_ssh_key() {
    local key_path="${SSH_DIR}/id_ed25519_signing"

    if [ -f "$key_path" ]; then
        print_info "$key_path already exists — using existing key"
        SIGNING_KEY_FOUND=true
        SIGNING_PUB_PATH="${key_path}.pub"
        return
    fi

    printf '  Generating ed25519 SSH key...\n' >&2

    local email
    email="$(git config --global --get user.email 2>/dev/null || true)"
    if [ -z "$email" ]; then
        printf '  Enter email for key comment: ' >&2
        read -r email </dev/tty || email="git-signing"
    fi

    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"

    ssh-keygen -t ed25519 -C "$email" -f "$key_path" </dev/tty

    if [ -f "${key_path}.pub" ]; then
        SIGNING_KEY_FOUND=true

        SIGNING_PUB_PATH="${key_path}.pub"
        print_info "Key generated: ${key_path}.pub"
    else
        print_warn "Key generation may have failed — ${key_path}.pub not found"
    fi
}

detect_fido2_sk_type() {
    # Determine whether the security key supports ed25519-sk (FIDO2) or only
    # ecdsa-sk (FIDO U2F). Prints "ed25519-sk" or "ecdsa-sk" to stdout.
    #
    # Detection order:
    #   1. ykman — checks for FIDO2 application support (vs U2F-only)
    #   2. fido2-token — probes device for ed25519 algorithm support
    #   3. Default to ed25519-sk — ssh-keygen will fail fast if unsupported
    if [ "$HAS_YKMAN" = true ]; then
        local ykman_out
        ykman_out="$(ykman info 2>/dev/null || true)"
        if printf '%s' "$ykman_out" | grep -qi 'FIDO2'; then
            printf 'ed25519-sk'
            return
        fi
        if printf '%s' "$ykman_out" | grep -qi 'FIDO\|U2F'; then
            printf 'ecdsa-sk'
            return
        fi
    fi
    if [ "$HAS_FIDO2_TOKEN" = true ]; then
        local device
        device="$(fido2-token -L 2>/dev/null | head -1 | cut -d: -f1-2 || true)"
        if [ -n "$device" ] && fido2-token -I "$device" 2>/dev/null | grep -qi 'ed25519'; then
            printf 'ed25519-sk'
            return
        fi
        if [ -n "$device" ]; then
            printf 'ecdsa-sk'
            return
        fi
    fi
    # Default — try ed25519-sk; generate_fido2_key handles the fallback
    printf 'ed25519-sk'
}

generate_fido2_key() {
    # Check for existing hardware-backed signing keys (both types)
    local key_path_ed="${SSH_DIR}/id_ed25519_sk_signing"
    local key_path_ec="${SSH_DIR}/id_ecdsa_sk_signing"

    if [ -f "$key_path_ed" ]; then
        print_info "$key_path_ed already exists — using existing key"
        SIGNING_KEY_FOUND=true
        SIGNING_PUB_PATH="${key_path_ed}.pub"
        return
    fi
    if [ -f "$key_path_ec" ]; then
        print_info "$key_path_ec already exists — using existing key"
        SIGNING_KEY_FOUND=true
        SIGNING_PUB_PATH="${key_path_ec}.pub"
        return
    fi

    if ! detect_fido2_hardware; then
        printf '\n  No FIDO2 security key detected.\n' >&2
        printf '  Please insert your security key and press Enter to continue (or q to go back): ' >&2
        local reply
        read -r reply </dev/tty || reply="q"
        if [ "$reply" = "q" ]; then
            return
        fi
        if ! detect_fido2_hardware; then
            print_warn "Still no FIDO2 hardware detected. Skipping."
            return
        fi
    fi

    # On Linux, ssh-keygen needs libfido2 for hardware-backed keys.
    # Check ldconfig cache first, then fall back to dpkg/rpm query.
    if [ "$PLATFORM" = "linux" ]; then
        local has_libfido2=false
        if ldconfig -p 2>/dev/null | grep -q libfido2; then
            has_libfido2=true
        elif command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W libfido2-1 >/dev/null 2>&1; then
            has_libfido2=true
        elif command -v rpm >/dev/null 2>&1 && rpm -q libfido2 >/dev/null 2>&1; then
            has_libfido2=true
        fi
        if [ "$has_libfido2" = false ]; then
            print_warn "libfido2 is not installed (required for hardware-backed SSH keys)."
            printf '  Install it with:\n' >&2
            if command -v apt-get >/dev/null 2>&1; then
                printf '    sudo apt-get install libfido2-1\n' >&2
            elif command -v dnf >/dev/null 2>&1; then
                printf '    sudo dnf install libfido2\n' >&2
            elif command -v pacman >/dev/null 2>&1; then
                printf '    sudo pacman -S libfido2\n' >&2
            else
                printf '    Install the libfido2 package for your distribution\n' >&2
            fi
            printf '  Then re-run this script.\n' >&2
            MISSING_DEPENDENCY=true
            return
        fi
    fi

    # On macOS, the system ssh-keygen lacks FIDO2 support. Homebrew's openssh
    # bundles ssh-sk-helper and builds FIDO2 into its own ssh-keygen binary.
    # Detect by checking for ssh-sk-helper (NOT by running ssh-keygen, which
    # would block waiting for a FIDO touch).
    local keygen_cmd="ssh-keygen"
    if [ "$PLATFORM" = "macos" ]; then
        local brew_keygen=""
        local brew_path brew_dir
        for brew_path in /opt/homebrew/bin/ssh-keygen /usr/local/bin/ssh-keygen; do
            [ -x "$brew_path" ] || continue
            # Resolve symlink to find the cellar libexec with ssh-sk-helper
            local real_path
            real_path="$(readlink "$brew_path" 2>/dev/null || true)"
            if [ -n "$real_path" ]; then
                # Relative symlink: resolve against parent dir
                brew_dir="$(cd "$(dirname "$brew_path")" && cd "$(dirname "$real_path")" && pwd)"
                if [ -x "${brew_dir}/../libexec/ssh-sk-helper" ]; then
                    brew_keygen="$brew_path"
                    break
                fi
            fi
        done
        if [ -z "$brew_keygen" ]; then
            print_warn "macOS system ssh-keygen lacks FIDO2 support."
            printf '  Install Homebrew OpenSSH (includes built-in FIDO2):\n' >&2
            printf '    brew install openssh\n' >&2
            printf '  Then re-run this script.\n' >&2
            MISSING_DEPENDENCY=true
            return
        fi
        keygen_cmd="$brew_keygen"
    fi

    # Detect best key type for this hardware
    local sk_type
    sk_type="$(detect_fido2_sk_type)"

    local email
    email="$(git config --global --get user.email 2>/dev/null || true)"
    if [ -z "$email" ]; then
        printf '  Enter email for key comment: ' >&2
        read -r email </dev/tty || email="git-signing"
    fi

    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"

    # Build an ordered list of key generation attempts as parallel arrays.
    # Each index holds one attempt: type, path, and whether to use -O resident.
    local attempt_types=() attempt_paths=() attempt_resident=()
    if [ "$sk_type" = "ecdsa-sk" ]; then
        attempt_types+=("ecdsa-sk")   attempt_paths+=("$key_path_ec") attempt_resident+=(false)
        attempt_types+=("ecdsa-sk")   attempt_paths+=("$key_path_ec") attempt_resident+=(true)
    else
        attempt_types+=("ed25519-sk") attempt_paths+=("$key_path_ed") attempt_resident+=(false)
        attempt_types+=("ecdsa-sk")   attempt_paths+=("$key_path_ec") attempt_resident+=(false)
        attempt_types+=("ecdsa-sk")   attempt_paths+=("$key_path_ec") attempt_resident+=(true)
    fi

    local key_path="" key_type_label="" resident=""
    local keygen_stderr keygen_rc
    local attempt_num=0
    # While loop with a manual index: "retry the same attempt" must NOT
    # advance to the next fallback (a for-in loop reassigns its variable on
    # every iteration, which silently broke the retry)
    local i=0
    local num_attempts=${#attempt_types[@]}

    while (( i < num_attempts )); do
        key_type_label="${attempt_types[$i]}"
        key_path="${attempt_paths[$i]}"
        resident="${attempt_resident[$i]}"

        attempt_num=$((attempt_num + 1))
        if (( attempt_num > 1 )); then
            local fallback_desc="$key_type_label"
            if [ "$resident" = true ]; then
                fallback_desc="${key_type_label} (-O resident)"
            fi
            print_warn "Falling back to ${fallback_desc}"
        fi

        local label="$key_type_label"
        if [ "$resident" = true ]; then
            label="${key_type_label} resident"
        fi
        printf '  Generating %s SSH key (touch your security key when prompted)...\n' "$label" >&2

        # Do NOT suppress stderr — per AC-7
        # Capture stderr to detect recoverable failures while still showing it
        local tmpstderr keygen_args
        tmpstderr="$(mktemp -t git-harden-keygen.XXXXXX)"
        keygen_args=(-t "$key_type_label" -C "$email" -f "$key_path")
        if [ "$resident" = true ]; then
            keygen_args+=(-O resident)
        fi
        "$keygen_cmd" "${keygen_args[@]}" </dev/tty 2>"$tmpstderr" && keygen_rc=0 || keygen_rc=$?
        keygen_stderr="$(cat "$tmpstderr")"
        rm -f "$tmpstderr"

        if [ -n "$keygen_stderr" ]; then
            printf '%s\n' "$keygen_stderr" >&2
        fi

        # Success
        if (( keygen_rc == 0 )) && [ -f "${key_path}.pub" ]; then
            break
        fi

        # Device not found — offer to plug in and retry the same attempt
        if printf '%s' "$keygen_stderr" | grep -qi 'device not found\|no device'; then
            rm -f "$key_path" "${key_path}.pub"
            printf '\n  Security key not detected.\n' >&2
            printf '  Please insert your security key and press Enter to retry (or q to skip): ' >&2
            local retry_reply
            read -r retry_reply </dev/tty || retry_reply="q"
            if [[ "$retry_reply" = "q" ]]; then
                return
            fi
            # Retry the same attempt: leave i unchanged
            attempt_num=$((attempt_num - 1))
            continue
        fi

        # Check for recoverable errors worth retrying with the next attempt
        if printf '%s' "$keygen_stderr" | grep -qi 'feature not supported\|unknown key type\|not supported\|invalid format'; then
            # Clean up any partial files before next attempt
            rm -f "$key_path" "${key_path}.pub"
            # Brief pause to let the authenticator reset its CTAP2 state
            # (back-to-back requests can cause spurious "invalid format")
            sleep 1
            i=$((i + 1))
            continue
        fi

        # Non-recoverable failure (user cancelled, wrong PIN, etc.)
        break
    done

    if [ -f "${key_path}.pub" ]; then
        SIGNING_KEY_FOUND=true
        SIGNING_PUB_PATH="${key_path}.pub"
        print_info "Key generated: ${key_path}.pub"
    else
        print_warn "Key generation failed. Common causes:"
        printf '  • Security key firmware does not support SSH key enrollment\n' >&2
        printf '  • Container/VM without full USB passthrough to the FIDO device\n' >&2
        printf '  • Outdated libfido2 — try updating to the latest version\n' >&2
        printf '  You can generate a software ed25519 key instead (option 1).\n' >&2
    fi
}

setup_allowed_signers() {
    if [ -z "$SIGNING_PUB_PATH" ] || [ ! -f "$SIGNING_PUB_PATH" ]; then
        return
    fi

    # Never write anything but public key material into allowed_signers
    if ! is_public_key_file "$SIGNING_PUB_PATH"; then
        print_warn "$SIGNING_PUB_PATH does not look like an SSH public key — refusing to add it to allowed_signers"
        return
    fi

    local email
    email="$(git config --global --get user.email 2>/dev/null || true)"
    if [[ -z "$email" ]]; then
        printf '  %ballowed_signers requires an email to match signatures.%b\n' "$YELLOW" "$RESET" >&2
        printf '  Enter your email (or press Enter to skip): ' >&2
        local input_email
        read -r input_email </dev/tty || input_email=""
        if [[ -n "$input_email" ]]; then
            email="$input_email"
        else
            print_warn "No email provided — skipping allowed_signers (signature verification will show 'No principal matched')"
            return
        fi
    fi

    SIGNING_PRINCIPAL="$email"

    mkdir -p "$(dirname "$ALLOWED_SIGNERS_FILE")"

    local pub_key
    pub_key="$(cat "$SIGNING_PUB_PATH")"

    # Check if this entry already exists
    if [ -f "$ALLOWED_SIGNERS_FILE" ]; then
        if grep -qF "$pub_key" "$ALLOWED_SIGNERS_FILE" 2>/dev/null; then
            print_info "Signing key already in allowed_signers"
            return
        fi
    fi

    printf '%s %s\n' "$email" "$pub_key" >> "$ALLOWED_SIGNERS_FILE"
    print_info "Added signing key to $ALLOWED_SIGNERS_FILE"
}

# ------------------------------------------------------------------------------
# SSH config hardening
# ------------------------------------------------------------------------------

# Read the current GLOBAL value of an SSH config directive (empty if absent).
# Global scope = top-level lines (before any Host/Match block) or lines inside
# a "Host *" block. Directives inside host-specific blocks do not apply
# globally and are deliberately ignored here.
get_ssh_directive_value() {
    local directive="$1"
    [ -f "$SSH_CONFIG" ] || return 0
    local raw
    raw="$(awk -v d="$(printf '%s' "$directive" | tr '[:upper:]' '[:lower:]')" '
        function ltrim(s) { sub(/^[ \t]+/, "", s); return s }
        {
            line = ltrim($0)
            lower = tolower(line)
        }
        lower ~ /^host[ \t=]/ {
            rest = substr(line, 5)
            sub(/^[ \t=]+/, "", rest)
            in_block = 1
            global_block = (rest == "*") ? 1 : 0
            next
        }
        lower ~ /^match[ \t=]/ { in_block = 1; global_block = 0; next }
        in_block && !global_block { next }
        index(lower, d) == 1 {
            sep = substr(lower, length(d) + 1, 1)
            if (sep == " " || sep == "\t" || sep == "=") {
                val = substr(line, length(d) + 1)
                sub(/^[ \t=]+/, "", val)
                print val
                exit
            }
        }
    ' "$SSH_CONFIG" 2>/dev/null || true)"
    strip_ssh_value "$raw"
}

# True if the last Host/Match block in the SSH config is exactly "Host *"
# (meaning new directives can be appended at EOF and land in global scope).
last_host_block_is_global() {
    awk '
        function ltrim(s) { sub(/^[ \t]+/, "", s); return s }
        {
            line = ltrim($0)
            lower = tolower(line)
        }
        lower ~ /^host[ \t=]/ {
            rest = substr(line, 5)
            sub(/^[ \t=]+/, "", rest)
            last = (rest == "*") ? 1 : 0
        }
        lower ~ /^match[ \t=]/ { last = 0 }
        END { exit last ? 0 : 1 }
    ' "$SSH_CONFIG" 2>/dev/null
}

ssh_directive_needs_change() {
    local directive="$1"
    local value="$2"
    [ "$(get_ssh_directive_value "$directive")" != "$value" ]
}

apply_single_ssh_directive() {
    local directive="$1"
    local value="$2"

    local current
    current="$(get_ssh_directive_value "$directive")"

    if [ -n "$current" ]; then
        # Replace the first GLOBAL-scope occurrence (top-level or inside a
        # "Host *" block). Occurrences inside host-specific blocks are left
        # alone — rewriting those would change behavior for that host only
        # while the global default stayed unset.
        local tmpfile
        tmpfile="$(mktemp "${SSH_CONFIG}.XXXXXX")"
        local replaced=false in_global=true line indent
        while IFS= read -r line || [ -n "$line" ]; do
            if printf '%s' "$line" | grep -qiE '^[[:space:]]*host[[:space:]=]'; then
                if printf '%s' "$line" | grep -qE '^[[:space:]]*[Hh][Oo][Ss][Tt][[:space:]=]+\*[[:space:]]*$'; then
                    in_global=true
                else
                    in_global=false
                fi
                printf '%s\n' "$line"
                continue
            fi
            if printf '%s' "$line" | grep -qiE '^[[:space:]]*match[[:space:]=]'; then
                in_global=false
                printf '%s\n' "$line"
                continue
            fi
            if [ "$replaced" = false ] && [ "$in_global" = true ] && \
               printf '%s' "$line" | grep -qi "^[[:space:]]*${directive}[[:space:]=]"; then
                indent="${line%%[![:space:]]*}"
                printf '%s%s %s\n' "$indent" "$directive" "$value"
                replaced=true
                continue
            fi
            printf '%s\n' "$line"
        done < "$SSH_CONFIG" > "$tmpfile"
        mv "$tmpfile" "$SSH_CONFIG"
        chmod 600 "$SSH_CONFIG"
        return 0
    fi

    # Directive not set globally — append at EOF. ssh uses first-obtained-wins
    # semantics, so appending keeps every existing (earlier) host-specific and
    # Host * setting authoritative; the new value only fills the gap.
    # Make sure the file ends with a newline before appending.
    if [ -s "$SSH_CONFIG" ] && [ -n "$(tail -c 1 "$SSH_CONFIG")" ]; then
        printf '\n' >> "$SSH_CONFIG"
    fi

    if ! grep -qiE '^[[:space:]]*(host|match)[[:space:]=]' "$SSH_CONFIG" 2>/dev/null; then
        # No blocks at all — safe to append bare (top-level = global)
        printf '%s %s\n' "$directive" "$value" >> "$SSH_CONFIG"
    elif last_host_block_is_global; then
        # File ends inside a "Host *" block — appending lands in global scope
        printf '    %s %s\n' "$directive" "$value" >> "$SSH_CONFIG"
    else
        # Start a new global defaults block at EOF
        {
            printf '\n# Added by git-harden.sh — global defaults (blocks above take precedence)\n'
            printf 'Host *\n'
            printf '    %s %s\n' "$directive" "$value"
        } >> "$SSH_CONFIG"
    fi
    chmod 600 "$SSH_CONFIG"
}

apply_ssh_directive_group() {
    local group_name="$1"
    local description="$2"
    shift 2

    # Collect pending changes (directives that need updating)
    local pending_keys=()
    local pending_vals=()
    local pending_explanations=()

    while [ $# -ge 3 ]; do
        local key="$1" value="$2" explanation="$3"
        shift 3
        if ssh_directive_needs_change "$key" "$value"; then
            pending_keys+=("$key")
            pending_vals+=("$value")
            pending_explanations+=("$explanation")
        fi
    done

    local count="${#pending_keys[@]}"

    if [ "$count" -eq 0 ]; then
        return 0
    fi

    printf '\n  %b%s%b\n' "$BOLD" "$group_name" "$RESET" >&2
    printf '  %s\n\n' "$description" >&2

    local i
    for ((i = 0; i < count; i++)); do
        printf '    %-45s %s\n' "${pending_keys[$i]} ${pending_vals[$i]}" "# ${pending_explanations[$i]}" >&2
    done
    printf '\n' >&2

    if prompt_yn "Apply these ${count} directives?"; then
        for ((i = 0; i < count; i++)); do
            apply_single_ssh_directive "${pending_keys[$i]}" "${pending_vals[$i]}"
        done
        print_info "Applied ${count} SSH directives"
    fi
}

# Print the key types of all available SSH keys: on-disk pubkeys plus keys
# loaded in the SSH agent (covers agent-backed setups like 1Password where no
# private key exists on disk).
list_ssh_key_types() {
    local f
    for f in "${SSH_DIR}"/*.pub; do
        if [ -f "$f" ]; then
            awk '{print $1}' "$f" 2>/dev/null || true
        fi
    done
    if command -v ssh-add >/dev/null 2>&1; then
        ssh-add -L 2>/dev/null | awk '{print $1}' || true
    fi
}

# True if at least one key passes the hardened algorithm policy.
has_modern_ssh_key() {
    local t
    while IFS= read -r t; do
        case "$t" in
            ssh-ed25519|sk-ssh-ed25519*|ecdsa-sha2-*|sk-ecdsa-sha2*) return 0 ;;
        esac
    done <<EOF
$(list_ssh_key_types)
EOF
    return 1
}

has_any_ssh_key() {
    [ -n "$(list_ssh_key_types)" ]
}

apply_ssh_config() {
    print_header "SSH Config Hardening"

    # Ensure ~/.ssh/ exists with correct permissions
    if [ ! -d "$SSH_DIR" ]; then
        mkdir -p "$SSH_DIR"
        chmod 700 "$SSH_DIR"
        print_info "Created $SSH_DIR with mode 700"
    fi

    # Ensure ~/.ssh/config exists with correct permissions
    if [ ! -f "$SSH_CONFIG" ]; then
        touch "$SSH_CONFIG"
        chmod 600 "$SSH_CONFIG"
        print_info "Created $SSH_CONFIG with mode 600"
    else
        # Back up existing SSH config before modifying
        local timestamp
        timestamp="$(date +%Y%m%d-%H%M%S)"
        local ssh_backup="${SSH_CONFIG}.pre-harden-${timestamp}"
        cp -p "$SSH_CONFIG" "$ssh_backup"
        print_info "SSH config backed up to $ssh_backup"
    fi

    apply_ssh_directive_group "Host Verification" \
        "Trust-on-first-use (TOFU): accept new host keys automatically, but reject
  changed keys (the actual MITM scenario). The default 'ask' just trains users
  to blindly type 'yes'. Hashing known_hosts prevents hostname enumeration if
  the file is exfiltrated." \
        "StrictHostKeyChecking"  "accept-new"  "Auto-accept new hosts, reject changed keys" \
        "HashKnownHosts"         "yes"          "Hash hostnames in known_hosts (privacy)"

    apply_ssh_directive_group "Key & Agent Management" \
        "Without IdentitiesOnly, ssh-agent offers ALL loaded keys to every server —
  a malicious server can enumerate which services you have access to.
  AddKeysToAgent reduces passphrase fatigue so developers actually use them." \
        "IdentitiesOnly"  "yes"  "Only offer keys explicitly configured (prevents key leakage)" \
        "AddKeysToAgent"  "yes"  "Auto-add keys to ssh-agent after first use"

    # Algorithm restrictions need two guards:
    #  1. OpenSSH < 8.5 spells the option differently, and an unknown option
    #     in ~/.ssh/config makes EVERY ssh invocation fail
    #  2. if the user's only keys are RSA/DSA, restricting algorithms locks
    #     them out of every server those keys authenticate to
    if [ -z "$PUBKEY_ALGOS_DIRECTIVE" ]; then
        print_info "Skipping SSH pubkey algorithm restrictions (OpenSSH version too old or unknown)"
        return 0
    fi

    if ssh_directive_needs_change "$PUBKEY_ALGOS_DIRECTIVE" "$PUBKEY_ALGO_LIST" && \
       has_any_ssh_key && ! has_modern_ssh_key; then
        print_warn "Only legacy (RSA/DSA) SSH keys found — restricting pubkey algorithms would LOCK YOU OUT of servers using those keys"
        if [ "$AUTO_YES" = true ]; then
            print_info "Skipping algorithm restrictions in -y mode. Generate an ed25519 key, then re-run."
            return 0
        fi
        if ! prompt_yn "Apply algorithm restrictions anyway? (breaks RSA/DSA key authentication)" "n"; then
            print_info "Skipped algorithm restrictions. Generate an ed25519 key, then re-run."
            return 0
        fi
    fi

    apply_ssh_directive_group "Algorithm Restrictions" \
        "Disables RSA and DSA negotiation entirely. This prevents downgrade attacks
  to weaker algorithms. May break connections to legacy servers that only
  support RSA — those servers should be upgraded (RSA-SHA1 deprecated since
  OpenSSH 8.7)." \
        "$PUBKEY_ALGOS_DIRECTIVE" "$PUBKEY_ALGO_LIST" \
            "Ed25519 + ECDSA (software and hardware-backed)"
}

# ------------------------------------------------------------------------------
# Admin recommendations
# ------------------------------------------------------------------------------

print_admin_recommendations() {
    print_header "Admin / Org-Level Recommendations"
    printf '  These are informational and cannot be applied by this script:\n\n' >&2
    printf '  • Enable branch protection rules on main branches\n' >&2
    printf '  • Enable GitHub vigilant mode (Settings → SSH and GPG keys → Flag unsigned commits)\n' >&2
    printf '  • Restrict force-pushes (disable or limit to admins)\n' >&2
    printf '  • Rotate personal access tokens regularly; prefer fine-grained tokens\n' >&2
    printf '  • Use short-lived credentials (GitHub App tokens, OIDC) in CI/CD\n' >&2
    printf '  • Require signed commits via branch protection (Require signed commits)\n' >&2
    printf '  • Audit deploy keys and service account access quarterly\n' >&2
    printf '  • If using hook frameworks (husky, lefthook, pre-commit), pin versions and review changes\n' >&2
    printf '  • Use separate signing keys per org to prevent cross-platform identity correlation (OSINT)\n' >&2
    printf '    Use git includeIf with gitdir: or hasconfig:remote.*.url: for per-org signing keys\n' >&2
    printf '\n' >&2
}

# ------------------------------------------------------------------------------
# Safety review gate
# ------------------------------------------------------------------------------

safety_review_gate() {
    # Skip in -y mode (user takes responsibility) or --audit (read-only)
    if [ "$AUTO_YES" = true ] || [ "$AUDIT_ONLY" = true ]; then
        return
    fi

    local script_path
    script_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

    printf '\n%b── Safety Review ──%b\n' "$BOLD" "$RESET" >&2
    printf '  Before running scripts that modify your system configuration,\n' >&2
    printf '  you should review them with a tool you trust.\n\n' >&2

    if ! prompt_yn "Have you reviewed this script (or had an AI assistant review it) for safety?" "n"; then
        local review_prompt="Review this shell script for security issues. Check that it only modifies git and SSH config, makes no network calls, and does not exfiltrate data. List every file it writes to."
        printf '\n  You can review this script by piping it to an AI coding assistant:\n\n' >&2
        printf '  %bClaude Code:%b\n' "$BOLD" "$RESET" >&2
        printf '    cat "%s" | claude "%s"\n\n' "$script_path" "$review_prompt" >&2
        printf '  %bGemini CLI:%b\n' "$BOLD" "$RESET" >&2
        printf '    cat "%s" | gemini -p "%s"\n\n' "$script_path" "$review_prompt" >&2
        printf '  %bManual review:%b\n' "$BOLD" "$RESET" >&2
        printf '    less "%s"\n\n' "$script_path" >&2
        exit 0
    fi
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

main() {
    parse_args "$@"
    safety_review_gate
    detect_platform
    check_dependencies

    if [ "$RESET_SIGNING" = true ]; then
        reset_signing
        exit 0
    fi

    # --- Audit phase ---
    AUDIT_OK=0
    AUDIT_WARN=0
    AUDIT_MISS=0
    TIER_SECURITY_ISSUES=0
    TIER_HYGIENE_ISSUES=0
    TIER_PREFERENCE_ISSUES=0
    set_tier security

    audit_git_config
    audit_precommit_hook
    audit_global_gitignore
    audit_credential_hygiene
    audit_signing
    audit_ssh_config
    audit_ssh_key_hygiene

    local audit_exit=0
    print_audit_report || audit_exit=$?

    if [ "$AUDIT_ONLY" = true ]; then
        # Only security-tier issues fail the audit — hygiene and preference
        # items are reported but don't gate CI/compliance checks
        if (( TIER_SECURITY_ISSUES > 0 )); then
            exit 2
        fi
        exit 0
    fi

    # If everything is already OK, nothing to do
    if [ "$audit_exit" -eq 0 ]; then
        print_info "All settings already match recommendations. Nothing to do."
        if [ "$MISSING_DEPENDENCY" = false ]; then
            print_admin_recommendations
        fi
        exit 0
    fi

    # --- Apply phase ---
    if [ "$AUTO_YES" = false ]; then
        printf '\n' >&2
        if ! prompt_yn "Proceed with hardening?"; then
            print_info "Aborted."
            exit 0
        fi
    fi

    backup_git_config
    apply_git_config
    apply_precommit_hook
    apply_dispatch_hooks
    apply_global_gitignore
    apply_signing_config
    apply_ssh_config

    # Only show admin recommendations if everything completed without
    # missing dependencies or incomplete signing setup
    if [ "$MISSING_DEPENDENCY" = false ] && [ "$SIGNING_KEY_FOUND" = true ]; then
        print_admin_recommendations
    fi

    print_info "Hardening complete. Re-run with --audit to verify."
}

main "$@"
