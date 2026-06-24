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
readonly VERSION="0.8.0"
readonly BACKUP_DIR="${HOME}/.config/git"
readonly HOOKS_DIR="${HOME}/.config/git/hooks"
readonly ALLOWED_SIGNERS_FILE="${HOME}/.config/git/allowed_signers"
readonly GLOBAL_GITIGNORE="${HOME}/.config/git/ignore"
readonly SSH_DIR="${HOME}/.ssh"
readonly SSH_CONFIG="${SSH_DIR}/config"

readonly PUBKEY_ALGO_LIST="ssh-ed25519,sk-ssh-ed25519@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com"

# Generic secret-assignment heuristic (v0.8 FR1). Catches FOO_TOKEN=…,
# export API_KEY=… style assignments in shell rc files. Hygiene-tier only.
# Keyword adjacency-anchored to the =/: separator (denoise), matches exactly
# one non-space/non-quote value byte (FR1.1 — never spans the value), and
# excludes $-references via the final [^[:space:]"'$] class. Common rg↔grep
# subset only (no \b/\d/\w/\s). Run case-insensitively via scan_quiet -i.
readonly SECRET_ASSIGN_ERE="(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)[[:space:]]*[:=][[:space:]]*[\"']?[^[:space:]\"'\$]"

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
MIGRATE=false
PLATFORM=""

# Bounded .env/JSON walk depth for the secret inventory (v0.8 FR2/FR5).
# Meaning: scan files whose parent directory is at most this many levels below
# $HOME (find -maxdepth is SCAN_DEPTH+1). Validated as a string before any
# arithmetic by parse_args (FR5).
SCAN_DEPTH=2

# Files flagged group/other-readable by the FR3 permission audit during the
# secret inventory. Populated by secret_perm_check; the apply phase offers a
# single grouped `chmod 600` over this list. De-duplicated by absolute path so
# a file surfaced by several detection methods is only listed once.
SECRET_PERM_FLAGGED=()

# Findings recorded by the secret inventory for the v0.8 FR4 1Password advisor.
# Each entry is "<advisor-key>\t<path>" (TAB-separated). The advisor consumes
# this after the inventory in both --audit and apply phases, mapping the key to
# a tailored migration step. Reset at the top of audit_secret_inventory so a
# re-run does not accumulate stale findings. The path is the absolute file path
# (or directory, for the GPG-keys finding) of the credential.
SECRET_FINDINGS=()

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

# Quiet, first-match content scan with ripgrep preferred and a grep fallback.
# Returns only a status: 0 = matched, 1 = no match, >=2 = error. The matched
# text is discarded by both engines and never emitted. A no-match (1) is an
# expected, non-fatal outcome, so call sites must guard this (if/||).
# Usage: scan_quiet [-i] <ere> <file>
scan_quiet() {
    local ignore_case=false
    if [[ "$1" == "-i" ]]; then
        ignore_case=true
        shift
    fi
    local ere="$1"
    local file="$2"

    if command -v rg >/dev/null 2>&1; then
        if [[ "$ignore_case" == true ]]; then
            LC_ALL=C rg --quiet --max-count=1 --no-config --ignore-case -e "$ere" -- "$file"
        else
            LC_ALL=C rg --quiet --max-count=1 --no-config -e "$ere" -- "$file"
        fi
        return $?
    fi

    if [[ "$ignore_case" == true ]]; then
        LC_ALL=C grep -qElim1 -e "$ere" -- "$file"
    else
        LC_ALL=C grep -qElm1 -e "$ere" -- "$file"
    fi
    return $?
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
    is_public_key_material "$first"
}

# True when the given STRING is OpenSSH public-key material (a key line, not a
# file). Used to guard against ever writing private material into
# allowed_signers when the key comes from an agent rather than a file.
is_public_key_material() {
    local line="$1"
    case "$line" in
        ssh-ed25519\ *|ssh-rsa\ *|ssh-dss\ *|ecdsa-sha2-*\ *|sk-ssh-ed25519*|sk-ecdsa-sha2*)
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
            --migrate)
                MIGRATE=true
                shift
                ;;
            --scan-depth)
                if [ $# -lt 2 ]; then
                    die "--scan-depth requires a non-negative integer argument. Use --help for usage."
                fi
                # Validate as a STRING regex BEFORE any arithmetic: a bad value
                # must cleanly die with usage, never abort on an arithmetic
                # error inside (( ... )) under errexit (FR5).
                if [[ ! "$2" =~ ^[0-9]+$ ]]; then
                    die "--scan-depth must be a non-negative integer (got '$2'). Use --help for usage."
                fi
                SCAN_DEPTH="$2"
                shift 2
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
  --migrate         Guided migration of on-disk private keys to a vault SSH
                    agent (1Password/Bitwarden). Prints import instructions,
                    then offers to remove migrated plaintext keys. Interactive
                    only — never runs or deletes anything in -y mode.
  --scan-depth N    Depth (directory levels below $HOME) for the bounded
                    .env/JSON secret-inventory walk. Non-negative integer,
                    default 2 (covers ~/projects/<repo>/.env). Composes with
                    --audit and -y.
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

# --- Secret inventory (v0.8 FR1) -------------------------------------------
#
# A fixed registry of plaintext / trivially-recoverable developer credentials
# beyond SSH keys. Each finding reports only its KIND and PATH at an explicit
# tier — never a value. Content detections go through the FR1.2 scan_quiet
# helper (ripgrep preferred, grep fallback, quiet/first-match), which is the
# single enforcement point for the FR1.1 minimal-read discipline. Phase 1
# covers fixed paths only; the bounded $HOME .env/JSON walk is Phase 2.

# Portable permission-bits query (FR3). Prints the file's octal mode string on
# stdout (e.g. 644, 0600, 4755) and returns 0; returns non-zero (printing
# nothing) when stat is unavailable or produces output that is not a 3- or
# 4-digit octal string, so the caller can WARN and skip the permission check
# while still reporting the finding. Linux uses `stat -c '%a'`; macOS/BSD uses
# `stat -f '%Lp'` (BSD %Lp emits no leading zero — handled by FR3 base-8 mask).
file_mode() {
    local f="$1"
    local mode=""
    case "$PLATFORM" in
        macos)
            mode="$(stat -f '%Lp' -- "$f" 2>/dev/null || true)"
            ;;
        linux)
            mode="$(stat -c '%a' -- "$f" 2>/dev/null || true)"
            ;;
        *)
            # Best-effort for an undetected platform: try GNU then BSD form.
            mode="$(stat -c '%a' -- "$f" 2>/dev/null || stat -f '%Lp' -- "$f" 2>/dev/null || true)"
            ;;
    esac
    if [[ ! "$mode" =~ ^[0-7]{3,4}$ ]]; then
        return 1
    fi
    printf '%s\n' "$mode"
}

# FR3 permission audit for one file finding. Computes the mode via file_mode,
# forces base-8 interpretation, and masks against 077 (group/other bits). A
# non-zero result records a hygiene finding "<path> is mode <NNN> (group/other
# readable)" and adds the file to SECRET_PERM_FLAGGED for the apply phase.
# stat failure → WARN and skip (the finding itself is already reported by the
# caller). Symlinks are still evaluated for reporting, but the apply phase
# (secret_perm_apply) re-checks and skips links/dirs/not-owned targets.
secret_perm_check() {
    local f="$1"
    # Only regular files have meaningful 600-able perms; directories (e.g. the
    # gcloud legacy dir, ~/.gnupg/...) are not chmod'd by this feature.
    [[ -f "$f" ]] || return 0

    local mode
    if ! mode="$(file_mode "$f")"; then
        print_warn "could not determine permissions of ${f} (stat unavailable/unexpected output) — permission check skipped"
        return 0
    fi

    # Force base-8: strip leading zeros (so 0600 is not read as a bad octal
    # literal), default an all-zero strip to 0, then mask the low 3 octal
    # digits against group/other (077). Decimal interpretation here would be a
    # silent correctness bug on the BSD no-leading-zero form (FR3).
    local stripped="${mode#"${mode%%[!0]*}"}"
    [[ -n "$stripped" ]] || stripped=0
    local low3="${stripped: -3}"
    if (( 8#${low3} & 8#77 )); then
        set_tier hygiene
        print_warn "${f} is mode ${mode} (group/other readable)"
        # De-duplicate: a file can be surfaced by multiple detection methods.
        local seen
        for seen in ${SECRET_PERM_FLAGGED[@]+"${SECRET_PERM_FLAGGED[@]}"}; do
            [[ "$seen" == "$f" ]] && return 0
        done
        SECRET_PERM_FLAGGED+=("$f")
    fi
}

# Record one inventory finding for the FR4 1Password advisor: append
# "<advisor-key>\t<path>" to SECRET_FINDINGS. De-duplicated by the (key, path)
# pair so a file surfaced by several detection methods yields one advisor step.
# The advisor key selects the migration mechanism (plugin:<cli>, config:<tool>,
# env-dotfile, agent-key, generic); it is NEVER derived from secret content.
secret_record_finding() {
    local key="$1" path="$2"
    local entry="${key}"$'\t'"${path}"
    local existing
    for existing in ${SECRET_FINDINGS[@]+"${SECRET_FINDINGS[@]}"}; do
        [[ "$existing" == "$entry" ]] && return 0
    done
    SECRET_FINDINGS+=("$entry")
}

# Emit an "exists" finding for a fixed-path file at the given tier.
# Reports the absolute path; never reads the file's contents. The trailing
# advisor-key argument records the finding for the FR4 1Password advisor.
secret_report_exists() {
    local tier="$1" kind="$2" file="$3" advisor_key="$4"
    [[ -e "$file" ]] || return 0
    set_tier "$tier"
    print_warn "${kind}: ${file}"
    secret_perm_check "$file"
    secret_record_finding "$advisor_key" "$file"
}

# Emit a content-gated finding: present AND scan_quiet matches <ere>. The
# content scan is gated behind [ ! -L ] so it is never pointed at a symlink
# (which would read through to the target). Per spec FR1 "Symlinks" and the
# Edge Cases table, a fixed-path entry that is a symlink is STILL reported (by
# its link path, at its tier) so a real symlinked credential file is never
# silently dropped; only the content scan is skipped for the link.
# Usage: secret_report_content [-i] <tier> <kind> <file> <ere> <advisor-key>
secret_report_content() {
    local ignore_case=false
    if [[ "$1" == "-i" ]]; then
        ignore_case=true
        shift
    fi
    local tier="$1" kind="$2" file="$3" ere="$4" advisor_key="$5"
    [[ -f "$file" ]] || return 0
    if [[ -L "$file" ]]; then
        # Report the link path without reading through it (no content scan).
        set_tier "$tier"
        print_warn "${kind}: ${file}"
        secret_perm_check "$file"
        secret_record_finding "$advisor_key" "$file"
        return 0
    fi
    if [[ "$ignore_case" == true ]]; then
        if scan_quiet -i "$ere" "$file"; then
            set_tier "$tier"
            print_warn "${kind}: ${file}"
            secret_perm_check "$file"
            secret_record_finding "$advisor_key" "$file"
        fi
    else
        if scan_quiet "$ere" "$file"; then
            set_tier "$tier"
            print_warn "${kind}: ${file}"
            secret_perm_check "$file"
            secret_record_finding "$advisor_key" "$file"
        fi
    fi
}

# Docker registry auth: a non-empty embedded "auth" string AND no external
# credential store (credsStore/credHelpers). The base64 blob is recoverable by
# any local process, so the wording avoids "plaintext".
secret_report_docker() {
    local file="${HOME}/.docker/config.json"
    [[ -f "$file" ]] || return 0
    if [[ -L "$file" ]]; then
        # Symlink: report the link path without reading through it.
        set_tier security
        print_warn "Docker registry auth (recoverable by any local process): ${file}"
        secret_perm_check "$file"
        secret_record_finding "config:docker" "$file"
        return 0
    fi
    if scan_quiet '"auth":[[:space:]]*"[^"]' "$file" \
        && ! scan_quiet '(credsStore|credHelpers)' "$file"; then
        set_tier security
        print_warn "Docker registry auth (recoverable by any local process): ${file}"
        secret_perm_check "$file"
        secret_record_finding "config:docker" "$file"
    fi
}

# GCP service-account JSON via the two-pass json-marker method: first the
# "service_account" type marker, then (only if that matched) "private_key".
# Neither pass captures content (FR1.1). Phase 1 applies this to the fixed
# gcloud legacy_credentials directory if present.
secret_report_json_marker() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    if [[ -L "$file" ]]; then
        # Symlink: report the link path without reading through it.
        set_tier security
        print_warn "GCP service-account key: ${file}"
        secret_perm_check "$file"
        secret_record_finding "config:gcloud" "$file"
        return 0
    fi
    if scan_quiet '"type"[[:space:]]*:[[:space:]]*"service_account"' "$file" \
        && scan_quiet '"private_key"' "$file"; then
        set_tier security
        print_warn "GCP service-account key: ${file}"
        secret_perm_check "$file"
        secret_record_finding "config:gcloud" "$file"
    fi
}

# Generic secret-assignment heuristic, hygiene-tier only, applied solely to
# files the script already reads (shell rc files). Findings are worded
# "secret-shaped assignment" — a heuristic signal, never "plaintext secret".
audit_secret_assign_files() {
    local f
    for f in "${HOME}/.zshrc" "${HOME}/.bashrc" "${HOME}/.bash_profile" \
             "${HOME}/.profile" "${HOME}/.zshenv"; do
        [[ -f "$f" ]] || continue
        [[ ! -L "$f" ]] || continue
        if scan_quiet -i "$SECRET_ASSIGN_ERE" "$f"; then
            set_tier hygiene
            print_warn "secret-shaped assignment in ${f}"
            secret_perm_check "$f"
            secret_record_finding "env-dotfile" "$f"
        fi
    done
}

# Fixed prune allowlist for the FR2 walk (directory basenames). This is a
# fixed allowlist, NOT a "dot-dir at depth >= 2" heuristic — anything outside
# this list within the depth bound is scanned. The same set is used to build
# the find predicate and to name the skipped dirs in the [INFO] coverage line.
# An array (not a space-joined string) so the elements survive IFS=$'\n\t'.
readonly SECRET_WALK_PRUNE_DIRS=(
    node_modules .git vendor .cache .cargo .rustup .npm
    Library .Trash .terraform pkg
)

# Canonical absolute path for de-duplication. Prefers realpath; falls back to
# cd&&pwd of the parent plus the basename (handles a non-existent realpath and
# stays correct for files). Prints the canonical path on stdout (data).
canonical_path() {
    local p="$1"
    if command -v realpath >/dev/null 2>&1; then
        local rp
        if rp="$(realpath -- "$p" 2>/dev/null)"; then
            printf '%s\n' "$rp"
            return 0
        fi
    fi
    local dir base
    dir="$(dirname -- "$p")"
    base="$(basename -- "$p")"
    local cdir
    if cdir="$(cd -- "$dir" 2>/dev/null && pwd)"; then
        if [[ "$cdir" == "/" ]]; then
            printf '/%s\n' "$base"
        else
            printf '%s/%s\n' "$cdir" "$base"
        fi
        return 0
    fi
    # Last resort: emit the path unchanged so a finding is never dropped.
    printf '%s\n' "$p"
}

# Run a single NUL-safe find pass and emit matching file paths NUL-delimited on
# stdout. BSD + GNU compatible: -maxdepth is given first (BSD requires global
# options before predicates); the fixed prune-dir allowlist is matched and
# -pruned BEFORE the file-match branch via grouped -o. Symlinks are not
# followed (no -L/-follow; file matches use -type f). find stderr (permission
# denied on unreadable subtrees) is suppressed.
# Usage: secret_walk_find <root> <maxdepth>
secret_walk_find() {
    local root="$1" maxdepth="$2"
    local prune
    # Build the directory-name prune predicate from the fixed allowlist.
    local -a name_pred=()
    local first=true
    for prune in "${SECRET_WALK_PRUNE_DIRS[@]}"; do
        if [[ "$first" == true ]]; then
            name_pred+=(-name "$prune")
            first=false
        else
            name_pred+=(-o -name "$prune")
        fi
    done

    LC_ALL=C find "$root" -maxdepth "$maxdepth" \
        \( -type d \( "${name_pred[@]}" \) -prune \) \
        -o \( -type f \( -name '.env' -o -name '.env.*' -o -name '*.json' \) -print0 \) \
        2>/dev/null
}

# Classify and report a single walked candidate file. .env / .env.* (excluding
# *.example/*.sample/*.template/*.dist) are hygiene-tier "exists" findings;
# *.json files are run through the FR1 json-marker method (security tier) so
# only genuine GCP service-account keys are reported. Content scans are gated
# behind [ ! -L ] inside secret_report_json_marker.
secret_walk_classify() {
    local f="$1"
    local base
    base="$(basename -- "$f")"
    case "$base" in
        *.example|*.sample|*.template|*.dist)
            return 0
            ;;
        .env|.env.*)
            set_tier hygiene
            print_warn ".env file: ${f}"
            secret_perm_check "$f"
            secret_record_finding "env-dotfile" "$f"
            ;;
        *.json)
            secret_report_json_marker "$f"
            ;;
    esac
}

# FR2 bounded walk: a single NUL-safe find over $HOME (to the configured depth)
# plus the current working directory's direct children (depth 0, even outside
# $HOME). Findings are de-duplicated by canonical path so a file reachable by
# both passes is reported once. Prints the [INFO] coverage line naming the
# depth and pruned dirs (no silent caps).
audit_secret_walk() {
    local maxdepth=$(( SCAN_DEPTH + 1 ))

    # Coverage line — explicit depth + pruned dirs (v0.6.0 "no silent caps").
    local pruned_list="" d
    for d in "${SECRET_WALK_PRUNE_DIRS[@]}"; do
        if [[ -z "$pruned_list" ]]; then
            pruned_list="$d"
        else
            pruned_list="${pruned_list}, ${d}"
        fi
    done
    print_info "scanned ~/ to depth ${SCAN_DEPTH}; skipped ${pruned_list}"

    # Track already-reported canonical paths to de-duplicate the $HOME walk and
    # the cwd scan. Newline-delimited; canonical paths never contain newlines
    # because realpath/pwd resolve to existing directories.
    local seen=$'\n'
    local f canon

    # 1. $HOME walk to maxdepth = SCAN_DEPTH + 1.
    while IFS= read -r -d '' f; do
        canon="$(canonical_path "$f")"
        case "$seen" in
            *$'\n'"$canon"$'\n'*) continue ;;
        esac
        seen="${seen}${canon}"$'\n'
        secret_walk_classify "$f"
    done < <(secret_walk_find "$HOME" "$maxdepth")

    # 2. Current working directory's direct children (depth 0), even if outside
    #    $HOME, so a developer running inside a checked-out repo sees its .env.
    local cwd
    cwd="$(pwd 2>/dev/null || true)"
    if [[ -n "$cwd" ]]; then
        while IFS= read -r -d '' f; do
            canon="$(canonical_path "$f")"
            case "$seen" in
                *$'\n'"$canon"$'\n'*) continue ;;
            esac
            seen="${seen}${canon}"$'\n'
            secret_walk_classify "$f"
        done < <(secret_walk_find "$cwd" 1)
    fi
}

audit_secret_inventory() {
    print_header "Secret Inventory"

    local before_warn="$AUDIT_WARN"

    # Reset the FR3 permission-flagged list and the FR4 advisor finding list so
    # a re-run does not accumulate stale entries (the apply phase and the
    # advisor each consume their list once after the audit).
    SECRET_PERM_FLAGGED=()
    SECRET_FINDINGS=()

    # --- Clear-cut credentials (tier = security) ---------------------------
    secret_report_exists security "git credentials (plaintext)" "${HOME}/.git-credentials" generic
    secret_report_content security "AWS static keys" "${HOME}/.aws/credentials" 'aws_secret_access_key' plugin:aws
    secret_report_exists security "GCP application-default credentials" "${HOME}/.config/gcloud/application_default_credentials.json" config:gcloud
    secret_report_content security "DigitalOcean token" "${HOME}/.config/doctl/config.yaml" 'access-token:' generic
    secret_report_exists security "Terraform Cloud token" "${HOME}/.terraform.d/credentials.tfrc.json" plugin:terraform
    secret_report_content security "Terraform Cloud token" "${HOME}/.terraformrc" 'credentials' plugin:terraform
    secret_report_content security "GitHub CLI token" "${HOME}/.config/gh/hosts.yml" 'oauth_token:' plugin:gh
    secret_report_content security "GitLab CLI token" "${HOME}/.config/glab-cli/config.yml" 'token:' plugin:glab
    secret_report_content security "npm token" "${HOME}/.npmrc" '_authToken=[^[:space:]]' config:npm
    secret_report_content security "Yarn token" "${HOME}/.yarnrc.yml" '^[[:space:]]*npmAuthToken:[[:space:]]*[^[:space:]#]' config:npm
    secret_report_content security "PyPI password/token" "${HOME}/.pypirc" '^[[:space:]]*password[[:space:]]*=[[:space:]]*[^[:space:]]' config:pypi
    # URL-embedded exception (FR1.1): spans : to @ by necessity.
    secret_report_content security "pip URL credentials (credentials embedded in a URL)" "${HOME}/.config/pip/pip.conf" '://[^/[:space:]]+:[^@/[:space:]]+@' config:pypi
    secret_report_exists security "RubyGems key" "${HOME}/.gem/credentials" config:rubygems
    secret_report_exists security "Cargo token" "${HOME}/.cargo/credentials.toml" config:cargo
    secret_report_exists security "Composer auth" "${HOME}/.config/composer/auth.json" config:composer
    secret_report_content security "Maven server password" "${HOME}/.m2/settings.xml" '<password>[^<$%]' config:maven
    secret_report_docker
    secret_report_content security "kubeconfig" "${HOME}/.kube/config" '(client-key-data:[[:space:]]*[^[:space:]]|[[:space:]]token:[[:space:]]*[^[:space:]])' config:kubeconfig
    secret_report_exists security "PostgreSQL password (.pgpass)" "${HOME}/.pgpass" config:pgpass
    secret_report_content security "MySQL password (.my.cnf)" "${HOME}/.my.cnf" 'password[[:space:]]*=' generic
    secret_report_exists security "MySQL login-path (recoverable by any local process)" "${HOME}/.mylogin.cnf" generic
    secret_report_exists security "Network credentials (.netrc)" "${HOME}/.netrc" config:netrc

    # GCP service-account JSON in the fixed gcloud legacy dir (json-marker).
    local legacy_dir="${HOME}/.config/gcloud/legacy_credentials"
    if [[ -d "$legacy_dir" ]]; then
        local jf
        for jf in "$legacy_dir"/*/adc.json "$legacy_dir"/*.json; do
            secret_report_json_marker "$jf"
        done
    fi

    # --- Noisy / heuristic credentials (tier = hygiene) --------------------
    secret_report_content hygiene "NuGet password" "${HOME}/.config/NuGet/NuGet.Config" 'ClearTextPassword' generic
    secret_report_content hygiene "Gradle properties" "${HOME}/.gradle/gradle.properties" '(password|signing\.(key|password)|apiKey)' generic
    audit_secret_assign_files

    # --- Bounded .env / scanned-JSON walk (FR2) ----------------------------
    audit_secret_walk

    # --- Informational ------------------------------------------------------
    local gpg_priv="${HOME}/.gnupg/private-keys-v1.d"
    if [[ -d "$gpg_priv" ]] && [[ -n "$(ls -A "$gpg_priv" 2>/dev/null || true)" ]]; then
        set_tier info
        print_info "GPG private keys present: ${gpg_priv}"
        secret_record_finding "agent-key" "$gpg_priv"
    fi

    # All-clear only when nothing at all was recorded — including info-tier
    # findings like GPG keys (which use print_info and don't bump AUDIT_WARN).
    # Otherwise we'd print "nothing detected" and then an advisor block for the
    # very finding we just claimed wasn't there.
    if (( AUDIT_WARN == before_warn )) && [ "${#SECRET_FINDINGS[@]}" -eq 0 ]; then
        set_tier security
        print_ok "No plaintext dev credentials detected"
    fi

    set_tier security
}

# --- 1Password migration advisor (v0.8 FR4) --------------------------------
#
# Runs after the inventory in BOTH --audit (print-only) and apply phases. It
# never calls `op` or requires an authenticated 1Password session; it only
# detects `op` via `command -v` to tailor the wording. Output is built solely
# from SECRET_FINDINGS (advisor-key + path recorded during the inventory) — it
# never re-reads any credential file. Prints NOTHING when the inventory found
# nothing. All printed paths are escaped with `printf %q` (display-only, never
# eval'd) so a path containing a quote/space cannot break the example.

# 1Password 'op plugin init' shell-plugin CLIs (FR4 fixed lookup table — single
# source of truth shared with the research doc). Adding a CLI means adding a row.
readonly OP_SHELL_PLUGIN_CLIS=(
    aws gh glab terraform vault stripe openai vercel circleci
)

# The install pointer printed once when `op` is absent (FR4).
readonly OP_INSTALL_URL="https://developer.1password.com/docs/cli/get-started/"

# Return " (also gitignored)" when the managed global gitignore
# (core.excludesFile) contains a pattern matching the finding's basename;
# otherwise the empty string. Display-only hint for the advisor (FR4). The
# excludesFile is read with a quiet, fixed-string match on the basename so a
# pattern like `.env` or `*.json` listed there is recognised.
secret_gitignored_suffix() {
    local path="$1"
    local excludes_file expanded base
    excludes_file="$(git config --global --get core.excludesFile 2>/dev/null || true)"
    [[ -n "$excludes_file" ]] || return 0
    expanded="${excludes_file/#\~/$HOME}"
    [[ -f "$expanded" ]] || return 0
    base="$(basename -- "$path")"
    # Match the literal basename (e.g. `.env`) anywhere in a gitignore line,
    # which also covers a bare `.env` entry or an `*.env`/`.env*` glob row.
    if LC_ALL=C grep -qF -- "$base" "$expanded" 2>/dev/null; then
        printf ' (also gitignored)'
    fi
}

# Print the per-file config-template / op-run example for a config-file CLI.
# The example is marked "‡ idiomatic — confirm with op --help" per FR4 because
# the exact op inject/op run invocation can drift between tool versions. Paths
# are %q-escaped. <config-key> is the advisor key minus its "config:" prefix.
secret_advisor_config_example() {
    local cli="$1" path="$2"
    local qpath
    qpath="$(printf '%q' "$path")"
    case "$cli" in
        kubeconfig)
            printf '    op inject -i %s.tpl -o %s   # replace tokens/keys with op:// refs\n' "$qpath" "$qpath" >&2
            ;;
        docker)
            printf '    op inject -i %s.tpl -o %s   # store the registry auth in a vault, reference it via op://\n' "$qpath" "$qpath" >&2
            ;;
        npm)
            printf '    op run -- npm publish   # with //registry/:_authToken=op://vault/item/token in %s\n' "$qpath" >&2
            ;;
        pypi)
            printf '    op run -- twine upload dist/*   # with password=op://vault/item/token in %s\n' "$qpath" >&2
            ;;
        netrc)
            printf '    op inject -i %s.tpl -o %s   # machine … password op://vault/item/token\n' "$qpath" "$qpath" >&2
            ;;
        pgpass)
            printf '    op inject -i %s.tpl -o %s   # host:port:db:user:op://vault/item/password\n' "$qpath" "$qpath" >&2
            ;;
        maven)
            printf '    op inject -i %s.tpl -o %s   # <password>op://vault/item/password</password>\n' "$qpath" "$qpath" >&2
            ;;
        cargo)
            printf '    op run -- cargo publish   # with token = "op://vault/item/token" in %s\n' "$qpath" >&2
            ;;
        composer)
            printf '    op inject -i %s.tpl -o %s   # store the auth.json token as an op:// ref\n' "$qpath" "$qpath" >&2
            ;;
        rubygems)
            printf '    op inject -i %s.tpl -o %s   # :rubygems_api_key: op://vault/item/key\n' "$qpath" "$qpath" >&2
            ;;
        gcloud)
            printf '    op document create %s   # store the service-account JSON as a vault document, then remove the file\n' "$qpath" >&2
            ;;
        *)
            printf '    op inject -i %s.tpl -o %s\n' "$qpath" "$qpath" >&2
            ;;
    esac
    printf '    ‡ idiomatic — confirm with op --help\n' >&2
}

# FR4 advisor. Consumes SECRET_FINDINGS; prints a tailored 1Password migration
# step per distinct finding. Shell-plugin CLIs get `op plugin init <cli>` (one
# block per CLI); config-file CLIs get the op inject/op run example for that
# file; generic .env/dotfiles get the op run --env-file pattern; SSH/GPG keys
# point at the v0.7 agent path (no duplication). When `op` is absent, the
# install URL prints once and the per-finding steps still print.
secret_advisor() {
    # Nothing found → print nothing (FR4).
    if (( ${#SECRET_FINDINGS[@]} == 0 )); then
        return 0
    fi

    print_header "1Password Migration Advisor"

    local op_present=true
    if ! command -v op >/dev/null 2>&1; then
        op_present=false
        print_info "The 1Password CLI (op) is not installed."
        printf '  Install it: %s\n' "$OP_INSTALL_URL" >&2
        printf '  Then move each credential below into a vault and delete the\n' >&2
        printf '  plaintext copy. The exact next step per credential follows.\n\n' >&2
    fi

    # Track which shell-plugin CLIs we have already advised so a CLI surfaced by
    # several files (e.g. ~/.terraformrc and credentials.tfrc.json) prints once.
    local plugins_done=$'\n'
    local entry key path cli is_plugin

    for entry in "${SECRET_FINDINGS[@]}"; do
        key="${entry%%$'\t'*}"
        path="${entry#*$'\t'}"

        case "$key" in
            plugin:*)
                cli="${key#plugin:}"
                # Validate against the fixed lookup table; only advise plugin
                # init for a CLI that actually has a 1Password shell plugin.
                is_plugin=false
                local p
                for p in "${OP_SHELL_PLUGIN_CLIS[@]}"; do
                    [[ "$p" == "$cli" ]] && { is_plugin=true; break; }
                done
                if [[ "$is_plugin" != true ]]; then
                    # Unknown plugin key — fall back to the generic principle.
                    secret_advisor_generic "$path"
                    continue
                fi
                case "$plugins_done" in
                    *$'\n'"$cli"$'\n'*) continue ;;
                esac
                plugins_done="${plugins_done}${cli}"$'\n'
                print_info "${cli}: use the 1Password shell plugin"
                printf '    op plugin init %s\n' "$cli" >&2
                printf '    then delete the plaintext file%s\n' "$(secret_gitignored_suffix "$path")" >&2
                ;;
            config:*)
                cli="${key#config:}"
                print_info "$(printf '%s: template the credential into 1Password%s' "$cli" "$(secret_gitignored_suffix "$path")")"
                secret_advisor_config_example "$cli" "$path"
                ;;
            env-dotfile)
                local qpath
                qpath="$(printf '%q' "$path")"
                print_info "$(printf 'dotfile/.env: load secrets from 1Password at runtime%s' "$(secret_gitignored_suffix "$path")")"
                printf '    op run --env-file=%s -- your-command   # values as op://vault/item/field\n' "$qpath" >&2
                printf '    or import it as a 1Password Environment (Developer → Environments)\n' >&2
                ;;
            agent-key)
                print_info "SSH/GPG keys: ${path}"
                printf '    Use the agent-backed key path (run git-harden.sh and accept the\n' >&2
                printf '    SSH-agent migration) so private keys live in 1Password, not on disk.\n' >&2
                ;;
            *)
                secret_advisor_generic "$path"
                ;;
        esac
    done

    if [[ "$op_present" == true ]]; then
        printf '\n' >&2
        print_info "Advisor only prints commands; it never runs op or touches your vault."
    fi
}

# Generic 1Password principle for a credential with no dedicated plugin or
# config-template path: store it in a vault and reference it via op://.
secret_advisor_generic() {
    local path="$1"
    local qpath
    qpath="$(printf '%q' "$path")"
    print_info "$(printf 'credential: store in 1Password, reference via op://%s' "$(secret_gitignored_suffix "$path")")"
    printf '    op item create / op read op://vault/item/field, then delete %s\n' "$qpath" >&2
}

# FR3 apply: offer a single grouped `chmod 600` over the files the permission
# audit flagged as group/other-readable. Interactive presents one prompt
# listing every file, default Yes (safe hardening, never destructive); -y
# applies automatically. Each chmod is guarded: a not-owned, not-writable,
# symlink, or directory target is skipped with a [WARN] and the run continues
# (must never abort under errexit). Not reached in --audit mode (read-only).
apply_secret_permissions() {
    # Nothing flagged → nothing to do (also covers an empty array under set -u).
    if (( ${#SECRET_PERM_FLAGGED[@]} == 0 )); then
        return 0
    fi

    print_header "Secret File Permissions"
    printf '  These files are readable by group/other. Tightening to 0600\n' >&2
    printf '  (owner read/write only) reduces the blast radius of a local\n' >&2
    printf '  compromise. This only tightens permissions; it never loosens.\n\n' >&2

    local f
    for f in "${SECRET_PERM_FLAGGED[@]}"; do
        printf '    chmod 600 %s\n' "$f" >&2
    done
    printf '\n' >&2

    if ! prompt_yn "Tighten these ${#SECRET_PERM_FLAGGED[@]} file(s) to 0600?" "y"; then
        print_info "Left file permissions unchanged."
        return 0
    fi

    local fixed=0
    for f in "${SECRET_PERM_FLAGGED[@]}"; do
        # Re-validate at apply time: the target must be a regular file, not a
        # symlink, owned by us, and writable. Any failure → WARN + skip, never
        # abort (set -o errexit is active in the apply phase).
        if [[ -L "$f" ]]; then
            print_warn "Skipped ${f}: is a symlink (not chmod'd)"
            continue
        fi
        if [[ ! -f "$f" ]]; then
            print_warn "Skipped ${f}: not a regular file"
            continue
        fi
        if [[ ! -O "$f" ]]; then
            print_warn "Skipped ${f}: not owned by the current user"
            continue
        fi
        if [[ ! -w "$f" ]]; then
            print_warn "Skipped ${f}: not writable"
            continue
        fi
        if chmod 600 "$f" 2>/dev/null; then
            fixed=$((fixed + 1))
        else
            print_warn "Skipped ${f}: chmod failed"
        fi
    done

    print_info "Tightened ${fixed} file(s) to 0600."
}

# Print candidate SSH agent sockets as "type<TAB>socket" lines (data, stdout).
# Sources, in order: SSH_AUTH_SOCK (generic, marked "forwarded" when a remote
# session is also indicated), 1Password, Bitwarden, gpg-agent. Sockets are only
# listed here; reachability is probed separately and read-only. No socket that
# does not exist as a path is emitted, EXCEPT SSH_AUTH_SOCK which may be an
# abstract/agent endpoint we still want to probe.
list_ssh_agent_sockets() {
    local seen=""
    local emit_type

    # 1. SSH_AUTH_SOCK — generic agent endpoint. A set SSH_CONNECTION or
    #    SSH_TTY alongside it indicates a forwarded agent.
    if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
        if [[ -n "${SSH_CONNECTION:-}" || -n "${SSH_TTY:-}" ]]; then
            emit_type="forwarded"
        else
            emit_type="ssh-auth-sock"
        fi
        printf '%s\t%s\n' "$emit_type" "${SSH_AUTH_SOCK}"
        seen="${seen}|${SSH_AUTH_SOCK}|"
    fi

    # 2. 1Password agent socket (macOS group container path, Linux dotfile path)
    local op_sock
    for op_sock in \
        "${HOME}/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock" \
        "${HOME}/.1password/agent.sock"; do
        if [[ -S "$op_sock" ]] && [[ "$seen" != *"|${op_sock}|"* ]]; then
            printf '1password\t%s\n' "$op_sock"
            seen="${seen}|${op_sock}|"
        fi
    done

    # 3. Bitwarden agent socket (default plus App Store / Snap / Flatpak paths)
    local bw_sock
    for bw_sock in \
        "${HOME}/.bitwarden-ssh-agent.sock" \
        "${HOME}/Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock" \
        "${HOME}/snap/bitwarden/current/.bitwarden-ssh-agent.sock" \
        "${HOME}/.var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock"; do
        if [[ -S "$bw_sock" ]] && [[ "$seen" != *"|${bw_sock}|"* ]]; then
            printf 'bitwarden\t%s\n' "$bw_sock"
            seen="${seen}|${bw_sock}|"
        fi
    done

    # 4. gpg-agent SSH socket (path reported by gpgconf)
    if command -v gpgconf >/dev/null 2>&1; then
        local gpg_sock
        gpg_sock="$(gpgconf --list-dirs agent-ssh-socket 2>/dev/null || true)"
        if [[ -n "$gpg_sock" ]] && [[ -S "$gpg_sock" ]] && [[ "$seen" != *"|${gpg_sock}|"* ]]; then
            printf 'gpg-agent\t%s\n' "$gpg_sock"
            seen="${seen}|${gpg_sock}|"
        fi
    fi
}

# Probe one agent socket READ-ONLY and print its public keys (one per line).
# Never writes to the socket: ssh-add -L only lists. Emits nothing if the agent
# is unreachable or empty.
agent_list_keys() {
    local sock="$1"
    command -v ssh-add >/dev/null 2>&1 || return 0
    local raw line
    raw="$(SSH_AUTH_SOCK="$sock" ssh-add -L 2>/dev/null || true)"
    # A reachable-but-empty agent prints the sentinel "The agent has no
    # identities." to STDOUT (not stderr) and exits 1. Keep only real public
    # key lines (those beginning with a known key-type token) so an empty agent
    # yields empty output and is not miscounted as holding one key.
    while IFS= read -r line; do
        case "$line" in
            ssh-*|ecdsa-*|sk-*) printf '%s\n' "$line" ;;
        esac
    done <<EOF
$raw
EOF
}

# List modern-algorithm public keys held by ALL reachable agents, deduplicated
# by key blob. One full public-key line per row ("<keytype> <blob> <comment>"),
# exactly as ssh-add -L prints it. Only ed25519, ed25519-sk, ecdsa, and
# ecdsa-sk are emitted — the same hardened policy as has_modern_ssh_key. Output
# is data, so it goes to stdout; this is the picker source for the wizard. The
# probe is read-only (ssh-add -L never writes to the socket).
list_modern_agent_keys() {
    local agent_type sock key blob seen=""
    while IFS=$'\t' read -r agent_type sock; do
        [[ -n "$sock" ]] || continue
        while IFS= read -r key; do
            [[ -n "$key" ]] || continue
            case "$key" in
                ssh-ed25519\ *|sk-ssh-ed25519*|ecdsa-sha2-*\ *|sk-ecdsa-sha2*) ;;
                *) continue ;;
            esac
            # Dedup by the base64 blob (field 2): the same key can surface
            # through several agents/sockets at once.
            blob="$(printf '%s' "$key" | awk '{print $2}')"
            [[ -n "$blob" ]] || continue
            if [[ "$seen" != *"|${blob}|"* ]]; then
                printf '%s\n' "$key"
                seen="${seen}|${blob}|"
            fi
        done <<INNER_EOF
$(agent_list_keys "$sock")
INNER_EOF
    done <<OUTER_EOF
$(list_ssh_agent_sockets)
OUTER_EOF
}

# Report every reachable SSH agent: type, reachability, key count. Read-only.
audit_ssh_agents() {
    print_header "SSH Agents"
    set_tier hygiene

    local found=false
    local line agent_type sock keys key_count
    while IFS=$'\t' read -r agent_type sock; do
        [[ -n "$agent_type" ]] || continue
        found=true
        keys="$(agent_list_keys "$sock")"
        if [[ -z "$keys" ]]; then
            # Distinguish unreachable from reachable-but-empty: ssh-add exit 2
            # means it could not contact the agent.
            if command -v ssh-add >/dev/null 2>&1; then
                # Put the probe in a tested context (|| rc=$?) so a nonzero exit
                # does not trip errexit and abort the whole audit. ssh-add exits
                # 2 when it cannot contact the agent (unreachable socket).
                local rc=0
                SSH_AUTH_SOCK="$sock" ssh-add -L >/dev/null 2>&1 || rc=$?
                if (( rc == 2 )); then
                    print_warn "SSH agent (${agent_type}) at ${sock} is unreachable"
                    continue
                fi
            fi
            print_info "SSH agent (${agent_type}) reachable at ${sock} — 0 keys loaded"
            continue
        fi
        # grep -c exits 1 when it counts zero lines; guard so a future caller
        # that reaches here with empty $keys cannot abort the audit under errexit.
        key_count="$(printf '%s\n' "$keys" | grep -c . || true)"
        print_ok "SSH agent (${agent_type}) reachable at ${sock} — ${key_count} key(s)"
    done <<EOF
$(list_ssh_agent_sockets)
EOF

    if [[ "$found" == false ]]; then
        print_info "No SSH agents detected"
    fi
    set_tier security
}

# Apply the weak-algorithm hygiene checks to a single public key.
# Arguments: key_type, label, bit_source_file (path to a .pub file used only to
# count RSA bits; may be empty for keys with no file, in which case the bit
# count is reported as unknown).
report_ssh_key_hygiene() {
    local key_type="$1"
    local label="$2"
    local bit_source="$3"
    local bits

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
            bits=""
            if [[ -n "$bit_source" ]] && [[ -f "$bit_source" ]]; then
                bits="$(ssh-keygen -l -f "$bit_source" 2>/dev/null | awk '{print $1}' || true)"
            fi
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

    # Track key blobs already reported (from disk) so agent keys holding the
    # same public key are deduplicated rather than listed twice.
    local seen_blobs=""
    local reported=false

    local key_type label blob
    if (( ${#pub_files[@]} > 0 )); then
        for f in "${pub_files[@]}"; do
            key_type="$(awk '{print $1}' "$f" 2>/dev/null || true)"
            blob="$(awk '{print $2}' "$f" 2>/dev/null || true)"
            label="$(basename "$f")"
            report_ssh_key_hygiene "$key_type" "$label" "$f"
            reported=true
            if [[ -n "$blob" ]]; then
                seen_blobs="${seen_blobs}|${blob}|"
            fi
        done
    fi

    # Merge agent-held keys, deduplicated against on-disk keys by key blob.
    local agent_type sock keys keyline tmppub
    while IFS=$'\t' read -r agent_type sock; do
        [[ -n "$agent_type" ]] || continue
        keys="$(agent_list_keys "$sock")"
        [[ -n "$keys" ]] || continue
        while IFS= read -r keyline; do
            [[ -n "$keyline" ]] || continue
            key_type="$(printf '%s' "$keyline" | awk '{print $1}')"
            blob="$(printf '%s' "$keyline" | awk '{print $2}')"
            # Dedupe against disk keys (and earlier agent keys) by blob
            if [[ -n "$blob" ]] && [[ "$seen_blobs" == *"|${blob}|"* ]]; then
                continue
            fi
            # Count RSA bits via a throwaway public-key file (read-only).
            tmppub="$(mktemp -t git-harden-agentkey.XXXXXX)"
            printf '%s\n' "$keyline" > "$tmppub"
            report_ssh_key_hygiene "$key_type" "(agent: ${agent_type})" "$tmppub"
            rm -f "$tmppub"
            reported=true
            if [[ -n "$blob" ]]; then
                seen_blobs="${seen_blobs}|${blob}|"
            fi
        done <<INNER_EOF
$keys
INNER_EOF
    done <<EOF
$(list_ssh_agent_sockets)
EOF

    if [[ "$reported" == false ]]; then
        print_info "No SSH public keys found"
    fi
}

# True if the file's first line is an OpenSSH or PEM private-key header. This
# identifies private keys by CONTENT, never by filename, so oddly-named keys
# are still caught and pubkeys/configs are never misclassified.
is_private_key_file() {
    local f="$1"
    [ -f "$f" ] || return 1
    local first
    first="$(head -1 "$f" 2>/dev/null || true)"
    # One glob covers every PEM/OpenSSH private-key header (OPENSSH/RSA/DSA/EC/
    # ENCRYPTED and the bare PKCS#8 form): "BEGIN " optionally a key-type word,
    # then "PRIVATE KEY-----". Written as a glob (not the literal headers) so it
    # stays a content marker rather than tripping secret scanners.
    case "$first" in
        "-----BEGIN "*"PRIVATE KEY-----")
            return 0 ;;
        *)
            return 1 ;;
    esac
}

# True if a private key file is UNENCRYPTED. We probe with the empty
# passphrase: `ssh-keygen -y -P "" -f <key>` derives the public key and
# succeeds only when no passphrase is needed. Runs in batch mode (no /dev/tty),
# so an encrypted key fails immediately instead of prompting. Read-only.
private_key_is_unencrypted() {
    local key="$1"
    ssh-keygen -y -P "" -f "$key" </dev/null >/dev/null 2>&1
}

# Audit: plaintext (unencrypted) private keys on disk in ~/.ssh.
# Candidates are enumerated by private-key header (never by filename). An
# unencrypted key is a security-tier WARN. An encrypted key whose public half
# is also held by an agent is an INFO (cleanup candidate). Audit-only: never
# modifies or deletes anything.
audit_ssh_private_keys() {
    print_header "On-disk Private Keys"
    set_tier security

    [ -d "$SSH_DIR" ] || { print_info "No ~/.ssh directory"; return; }

    # Build the set of public-key blobs held by all reachable agents so we can
    # flag encrypted on-disk keys that already live in an agent.
    local agent_blobs=""
    local agent_type sock keys keyline blob
    while IFS=$'\t' read -r agent_type sock; do
        [[ -n "$agent_type" ]] || continue
        keys="$(agent_list_keys "$sock")"
        [[ -n "$keys" ]] || continue
        while IFS= read -r keyline; do
            [[ -n "$keyline" ]] || continue
            blob="$(printf '%s' "$keyline" | awk '{print $2}')"
            [[ -n "$blob" ]] && agent_blobs="${agent_blobs}|${blob}|"
        done <<INNER_EOF
$keys
INNER_EOF
    done <<EOF
$(list_ssh_agent_sockets)
EOF

    local found=false
    local f label pub_blob
    for f in "${SSH_DIR}"/*; do
        [ -f "$f" ] || continue
        is_private_key_file "$f" || continue
        found=true
        label="$(basename "$f")"

        if private_key_is_unencrypted "$f"; then
            print_warn "Unencrypted private key on disk: ${f} — import into a vault/agent (1Password, Bitwarden) or add a passphrase, then remove the plaintext key"
            continue
        fi

        # Encrypted key. If its public half is held by an agent, it is a
        # candidate for cleanup once migration is confirmed.
        pub_blob=""
        if [ -f "${f}.pub" ]; then
            pub_blob="$(awk '{print $2}' "${f}.pub" 2>/dev/null || true)"
        fi
        if [[ -n "$pub_blob" ]] && [[ "$agent_blobs" == *"|${pub_blob}|"* ]]; then
            print_info "Encrypted private key ${label} is also held by an agent — candidate for cleanup once migration is confirmed"
        else
            print_ok "Private key ${label} is encrypted (passphrase-protected)"
        fi
    done

    if [[ "$found" == false ]]; then
        print_info "No private keys found on disk in ~/.ssh"
    fi
}

# Audit a fileless signing key (inline "ssh-*" value or the public-key material
# behind a "key::" value). Reports OK, then confirms allowed_signers carries the
# same public-key blob so verification will actually match a principal.
audit_inline_signing_key() {
    local key_material="$1"
    local label="$2"

    if ! is_public_key_material "$key_material"; then
        print_warn "user.signingkey = ($label) but the value is not valid SSH public-key material"
        return
    fi

    local blob
    blob="$(printf '%s' "$key_material" | awk '{print $2}')"

    if [ -n "$blob" ] && [ -f "$ALLOWED_SIGNERS_FILE" ] && \
       grep -qF "$blob" "$ALLOWED_SIGNERS_FILE" 2>/dev/null; then
        print_ok "user.signingkey = ($label) — present in allowed_signers"
    else
        print_warn "user.signingkey = ($label) but its key is not in allowed_signers (verification will show 'No principal matched')"
    fi
}

audit_signing() {
    print_header "Signing Configuration"

    # Pin the tier explicitly: set_tier is sticky, and a prior section may have
    # left it at hygiene. Without this, the "key:: not in allowed_signers" WARN
    # (via audit_inline_signing_key) could be miscounted as hygiene and let a
    # misconfigured-signing machine pass --audit.
    set_tier security

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
            case "$signing_key" in
                key::*)
                    # Agent-backed literal key (Git 2.34+). No file on disk; the
                    # private half lives in an agent. Verify allowed_signers
                    # carries the same public-key blob, otherwise verification
                    # will show "No principal matched".
                    audit_inline_signing_key "${signing_key#key::}" "agent key"
                    ;;
                ssh-*|ecdsa-*|sk-*)
                    audit_inline_signing_key "$signing_key" "inline key"
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

    # ForwardAgent: safe default is unset or "no" globally. "yes" in global
    # scope lets any root user on every host you connect to use your keys for
    # the duration of the session.
    set_tier security
    local fa
    fa="$(get_ssh_directive_value "ForwardAgent")"
    case "$fa" in
        "")
            print_ok "SSH: ForwardAgent unset globally (agent not forwarded by default)"
            ;;
        no|No|NO)
            print_ok "SSH: ForwardAgent = $fa"
            ;;
        yes|Yes|YES)
            print_warn "SSH: ForwardAgent = $fa globally — any root user on a host you connect to can use your keys while connected; scope it per-host and prefer a confirmation-prompting agent (1Password, ssh-add -c)"
            ;;
        *)
            print_warn "SSH: ForwardAgent = $fa (expected: no or unset globally)"
            ;;
    esac
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
            # No file-based key. If EXACTLY ONE modern key is loaded in an
            # agent, adopt it (mirrors the file-based "found existing key"
            # auto-pick); otherwise stay passive. The smoke test is always
            # skipped in -y mode, so no agent approval prompt can block.
            local agent_keys agent_key_count
            agent_keys="$(list_modern_agent_keys)"
            agent_key_count="$(printf '%s' "$agent_keys" | grep -c . || true)"
            if [ -n "$agent_keys" ] && [ "$agent_key_count" -eq 1 ]; then
                enable_signing_agent_key "$agent_keys"
            else
                print_info "No SSH signing key found. Skipping commit.gpgsign and tag.gpgsign."
                print_info "Run git-harden.sh interactively (without -y) to set up signing."
            fi
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

    # Offer an agent-backed key when at least one modern key is loaded in a
    # reachable agent — no key file ever touches disk.
    local agent_keys
    agent_keys="$(list_modern_agent_keys)"

    # Offer key generation options
    printf '\n  Signing key options:\n' >&2
    printf '    1) Generate a new ed25519 SSH key (software)\n' >&2
    printf '    2) Generate a hardware-backed SSH key (FIDO2/U2F security key)\n' >&2
    if [ -n "$agent_keys" ]; then
        printf '    3) Use a key from your SSH agent (no key file on disk)\n' >&2
    fi
    printf '    s) Skip signing setup (e.g. in an agent container where humans sign at PR merge)\n' >&2

    local choice
    if [ -n "$agent_keys" ]; then
        printf '\n  Choose [1/2/3/s]: ' >&2
    else
        printf '\n  Choose [1/2/s]: ' >&2
    fi
    read -r choice </dev/tty || choice="s"

    case "$choice" in
        1)
            generate_ssh_key
            ;;
        2)
            generate_fido2_key
            ;;
        3)
            if [ -z "$agent_keys" ]; then
                print_info "No agent keys available — skipping signing setup."
                return
            fi
            signing_wizard_agent_key "$agent_keys"
            return
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

# Let the user pick one of the modern agent-held keys (newline-separated full
# public-key lines), then enable agent-backed signing for it. With a single
# key, confirm and adopt; with several, prompt for an index.
signing_wizard_agent_key() {
    local agent_keys="$1"

    local keys=()
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] && keys+=("$line")
    done <<EOF
$agent_keys
EOF

    if (( ${#keys[@]} == 0 )); then
        print_info "No agent keys available — skipping signing setup."
        return
    fi

    local chosen
    if (( ${#keys[@]} == 1 )); then
        printf '\n  Agent key: %s\n' "$(agent_key_label "${keys[0]}")" >&2
        if ! prompt_yn "Use this agent key for git signing?"; then
            print_info "Skipping signing setup."
            return
        fi
        chosen="${keys[0]}"
    else
        printf '\n  Keys loaded in your SSH agent:\n' >&2
        local i
        for (( i = 0; i < ${#keys[@]}; i++ )); do
            printf '    %d) %s\n' "$(( i + 1 ))" "$(agent_key_label "${keys[$i]}")" >&2
        done
        local pick
        printf '\n  Choose a key [1-%d] (or s to skip): ' "${#keys[@]}" >&2
        read -r pick </dev/tty || pick="s"
        if ! [[ "$pick" =~ ^[0-9]+$ ]] || (( pick < 1 || pick > ${#keys[@]} )); then
            print_info "No key selected — skipping signing setup."
            return
        fi
        chosen="${keys[$(( pick - 1 ))]}"
    fi

    enable_signing_agent_key "$chosen"
}

# Render a human-readable label for an agent public-key line: "<keytype>
# <comment> (<fingerprint-prefix>)". Falls back gracefully when no comment.
agent_key_label() {
    local key="$1"
    local keytype comment
    keytype="$(printf '%s' "$key" | awk '{print $1}')"
    comment="$(printf '%s' "$key" | awk '{$1=""; $2=""; sub(/^[ \t]+/, ""); print}')"
    if [ -n "$comment" ]; then
        printf '%s %s' "$keytype" "$comment"
    else
        printf '%s (no comment)' "$keytype"
    fi
}

# Print the base64 key blobs (field 2) of every public key held by all
# reachable agents, one per line (data, stdout). Read-only probe. Used by the
# migration assistant to tell whether an on-disk key already lives in an agent.
list_agent_pub_blobs() {
    local agent_type sock keys keyline blob
    while IFS=$'\t' read -r agent_type sock; do
        [[ -n "$agent_type" ]] || continue
        keys="$(agent_list_keys "$sock")"
        [[ -n "$keys" ]] || continue
        while IFS= read -r keyline; do
            [[ -n "$keyline" ]] || continue
            blob="$(printf '%s' "$keyline" | awk '{print $2}')"
            [[ -n "$blob" ]] && printf '%s\n' "$blob"
        done <<INNER_EOF
$keys
INNER_EOF
    done <<EOF
$(list_ssh_agent_sockets)
EOF
}

# Derive the public-key blob (field 2) for an on-disk private key. Prefers a
# sibling .pub file; falls back to deriving the public half with
# `ssh-keygen -y` in batch mode (works only for an unencrypted key — an
# encrypted one fails silently and yields an empty blob without prompting).
# Read-only. Emits nothing when the blob cannot be determined.
private_key_pub_blob() {
    local key="$1"
    local blob=""
    if [ -f "${key}.pub" ]; then
        blob="$(awk 'NR==1{print $2}' "${key}.pub" 2>/dev/null || true)"
    fi
    if [ -z "$blob" ]; then
        blob="$(ssh-keygen -y -P "" -f "$key" </dev/null 2>/dev/null | awk 'NR==1{print $2}' || true)"
    fi
    [ -n "$blob" ] && printf '%s' "$blob"
}

# Print vault-import instructions for the detected agent type(s). PRINT ONLY:
# never invokes op/bw/bws — their CLIs change and require auth sessions. The
# agent type comes from list_ssh_agent_sockets (1password, bitwarden, …); when
# no vault agent is detected, generic guidance for both is printed.
print_vault_import_instructions() {
    local key="$1"
    local saw_vault=false
    local agent_type sock
    while IFS=$'\t' read -r agent_type sock; do
        [[ -n "$agent_type" ]] || continue
        case "$agent_type" in
            1password)
                saw_vault=true
                printf '\n  %b1Password%b — import %s:\n' "$BOLD" "$RESET" "$key" >&2
                printf '    1. Open the 1Password app → New Item → SSH Key → "Import a private key".\n' >&2
                printf '    2. Select %s (the private key file).\n' "$key" >&2
                printf '    3. Settings → Developer → enable "Use the SSH agent".\n' >&2
                printf '    4. Ensure SSH_AUTH_SOCK points at the 1Password agent socket\n' >&2
                printf '       (or set IdentityAgent — re-run git-harden without --migrate to apply it).\n' >&2
                ;;
            bitwarden)
                saw_vault=true
                printf '\n  %bBitwarden%b — import %s:\n' "$BOLD" "$RESET" "$key" >&2
                printf '    1. Open the Bitwarden desktop app → New Item → SSH Key.\n' >&2
                printf '    2. Paste the private key contents of %s into the "Private key" field\n' "$key" >&2
                printf '       (the app derives the public key and fingerprint).\n' >&2
                printf '    3. Settings → enable "Use SSH agent".\n' >&2
                printf '    4. Point SSH_AUTH_SOCK at ~/.bitwarden-ssh-agent.sock.\n' >&2
                ;;
        esac
    done <<EOF
$(list_ssh_agent_sockets)
EOF

    if [ "$saw_vault" = false ]; then
        printf '\n  No 1Password/Bitwarden agent detected. Import %s into your vault of choice:\n' "$key" >&2
        printf '    • 1Password: app → New Item → SSH Key → Import a private key, then enable\n' >&2
        printf '      the SSH agent under Settings → Developer.\n' >&2
        printf '    • Bitwarden: app → New Item → SSH Key, paste the private key, then enable\n' >&2
        printf '      "Use SSH agent" under Settings.\n' >&2
        printf '  Re-run "git-harden --migrate" once the agent is running so it can confirm\n' >&2
        printf '  the key and offer to remove the plaintext copy.\n' >&2
    fi
}

# Offer to remove a migrated on-disk private key under the v0.6.0 reset-signing
# safety rules: interactive only (never in -y), default No, with a rename-to-.bak
# middle option, and the .pub stub is ALWAYS kept so IdentitiesOnly keeps
# offering the now-agent-held key. Removes only the private half.
migration_offer_delete() {
    local key="$1"

    # Deleting key material is irreversible — never without an explicit,
    # interactive yes (prompt_yn auto-accepts in -y, so guard AUTO_YES first).
    if [ "$AUTO_YES" = true ]; then
        print_info "Key files left in place (-y mode never deletes keys)."
        return
    fi

    local backup_suffix
    backup_suffix=".bak.$(date +%Y%m%dT%H%M%S)"

    printf '\n  The agent now holds this key. The on-disk private key %s is redundant.\n' "$key" >&2
    printf '  Its .pub stub will be KEPT so IdentitiesOnly keeps offering the agent key.\n' >&2

    if prompt_yn "Delete the on-disk private key ${key}? (irreversible)" "n"; then
        rm -f "$key"
        print_info "Deleted private key $key (kept ${key}.pub stub)"
    elif prompt_yn "Rename it to ${key}${backup_suffix} instead? (No = leave untouched)" "n"; then
        mv "$key" "${key}${backup_suffix}"
        print_info "Renamed private key to ${key}${backup_suffix} (kept ${key}.pub stub)"
    else
        print_info "Left $key in place"
    fi
}

# Migration assistant (v0.7 Phase 4). Interactive only, opt-in via --migrate.
# Walks a file-based user toward zero plaintext private keys on disk:
#   1. Inventory on-disk private keys; show which are already held by an agent.
#   2. Print per-agent vault-import instructions (print only — never drives CLIs).
#   3. After the user confirms a key is imported AND the agent probe shows its
#      public key, offer deletion under the v0.6.0 reset-signing safety rules.
#   4. Re-run the relevant audits to show the end state.
run_migration() {
    print_header "Key Migration Assistant"

    # AC-2 belt-and-braces: this path is interactive only and must never run
    # under -y. main() already gates this, but guard here too.
    if [ "$AUTO_YES" = true ]; then
        print_info "Migration is interactive only and never runs in -y mode. Re-run without -y."
        return
    fi

    if [ ! -d "$SSH_DIR" ]; then
        print_info "No ~/.ssh directory — nothing to migrate."
        return
    fi

    # Inventory on-disk private keys (by content, never by filename).
    local priv_keys=()
    local f
    for f in "${SSH_DIR}"/*; do
        [ -f "$f" ] || continue
        is_private_key_file "$f" || continue
        priv_keys+=("$f")
    done

    if (( ${#priv_keys[@]} == 0 )); then
        print_info "No on-disk private keys found in ~/.ssh — already at zero plaintext keys."
        return
    fi

    # Snapshot the public blobs currently held by all reachable agents.
    local agent_blobs=""
    local blob
    while IFS= read -r blob; do
        [ -n "$blob" ] || continue
        agent_blobs="${agent_blobs}|${blob}|"
    done <<EOF
$(list_agent_pub_blobs)
EOF

    printf '\n  On-disk private keys in %s:\n' "$SSH_DIR" >&2
    local key pub_blob in_agent
    for key in "${priv_keys[@]}"; do
        pub_blob="$(private_key_pub_blob "$key")"
        if [ -n "$pub_blob" ] && [[ "$agent_blobs" == *"|${pub_blob}|"* ]]; then
            printf '    %s  (already in an agent)\n' "$key" >&2
        else
            printf '    %s\n' "$key" >&2
        fi
    done

    # Walk each key: print import instructions, confirm import + agent probe,
    # then offer deletion.
    for key in "${priv_keys[@]}"; do
        printf '\n%b── %s ──%b\n' "$BOLD" "$key" "$RESET" >&2

        pub_blob="$(private_key_pub_blob "$key")"
        in_agent=false
        if [ -n "$pub_blob" ] && [[ "$agent_blobs" == *"|${pub_blob}|"* ]]; then
            in_agent=true
        fi

        if [ "$in_agent" = false ]; then
            print_vault_import_instructions "$key"
            if ! prompt_yn "Have you imported ${key} into a vault agent?" "n"; then
                print_info "Skipping ${key} — import it, then re-run --migrate."
                continue
            fi
            # Re-probe the agent: the import is only confirmed once the agent
            # actually holds this key's public half.
            agent_blobs=""
            while IFS= read -r blob; do
                [ -n "$blob" ] || continue
                agent_blobs="${agent_blobs}|${blob}|"
            done <<EOF
$(list_agent_pub_blobs)
EOF
            pub_blob="$(private_key_pub_blob "$key")"
            if [ -z "$pub_blob" ] || [[ "$agent_blobs" != *"|${pub_blob}|"* ]]; then
                print_warn "The agent does not yet hold ${key}'s public key — not offering deletion. Verify the import and that the agent is running."
                continue
            fi
            print_info "Confirmed: the agent now holds ${key}'s public key."
        else
            print_info "${key} is already held by an agent."
        fi

        migration_offer_delete "$key"
    done

    # Re-run the relevant audits to show the end state.
    print_header "Migration End State"
    set_tier security
    audit_ssh_agents
    audit_ssh_key_hygiene
    audit_ssh_private_keys
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

# Enable signing with an agent-held public key (no file on disk). Sets
# user.signingkey to the literal "key::<keytype> <blob> <comment>" form Git
# 2.34+ understands for gpg.format=ssh, writes the matching allowed_signers
# entry from the same material, then smoke-tests through the agent.
enable_signing_agent_key() {
    local pub_key="$1"
    if ! is_public_key_material "$pub_key"; then
        print_warn "Selected agent key does not look like an SSH public key — not enabling signing"
        return
    fi
    git config --global user.signingkey "key::${pub_key}"
    git config --global commit.gpgsign true
    git config --global tag.gpgsign true
    git config --global tag.forceSignAnnotated true
    print_info "Signing enabled: commits and tags will be signed with an agent-held key (no key file on disk)"
    setup_allowed_signers "$pub_key"
    verify_signing_setup "" "$pub_key"
}

# Smoke-test the signing setup: sign a test message and verify it against
# allowed_signers with the recorded principal. Catches the "Good signature
# but No principal matched" misconfiguration at setup time instead of in
# every future `git log`.
verify_signing_setup() {
    local pub_path="$1"
    local pub_key="${2:-}"
    local priv_path="${pub_path%.pub}"

    # Signing may require a hardware-key touch or a passphrase — never
    # attempt it in non-interactive mode
    if [ "$AUTO_YES" = true ]; then
        return 0
    fi
    if [ -z "$SIGNING_PRINCIPAL" ] || [ ! -f "$ALLOWED_SIGNERS_FILE" ]; then
        return 0
    fi

    # Two paths: a private key file next to the .pub (file-based), or an
    # agent-held key (the private half lives in the agent — sign with -U).
    local agent_mode=false
    if [ -n "$pub_key" ]; then
        agent_mode=true
    elif [ ! -f "$priv_path" ]; then
        return 0
    fi

    if ! prompt_yn "Verify signing works now? (may require a key touch, passphrase, or agent approval)"; then
        return 0
    fi

    local tmpdir
    tmpdir="$(mktemp -d -t git-harden-verify.XXXXXX)"
    printf 'git-harden signing verification\n' > "${tmpdir}/msg"

    local verify_ok=false
    # Keep sign stderr visible — it carries the touch/passphrase/approval prompts
    if [ "$agent_mode" = true ]; then
        # The private half lives in the agent: write the public key to a temp
        # file and sign with -U (use the agent for the matching private key).
        printf '%s\n' "$pub_key" > "${tmpdir}/key.pub"
        if ssh-keygen -Y sign -U -n git -f "${tmpdir}/key.pub" "${tmpdir}/msg" >/dev/null && \
           ssh-keygen -Y verify -n git -f "$ALLOWED_SIGNERS_FILE" -I "$SIGNING_PRINCIPAL" \
               -s "${tmpdir}/msg.sig" < "${tmpdir}/msg" >/dev/null 2>&1; then
            verify_ok=true
        fi
    elif ssh-keygen -Y sign -n git -f "$priv_path" "${tmpdir}/msg" >/dev/null && \
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

# Add the signing key to allowed_signers. Accepts EITHER:
#   - no argument: read public-key material from the file at $SIGNING_PUB_PATH
#   - one argument: a literal public-key line (agent-held key, no file on disk)
# In both cases the material is validated as a public key before it is written,
# so private material can never leak into allowed_signers.
setup_allowed_signers() {
    local pub_key="${1:-}"

    if [ -n "$pub_key" ]; then
        if ! is_public_key_material "$pub_key"; then
            print_warn "Provided signing key material is not an SSH public key — refusing to add it to allowed_signers"
            return
        fi
    else
        if [ -z "$SIGNING_PUB_PATH" ] || [ ! -f "$SIGNING_PUB_PATH" ]; then
            return
        fi
        # Never write anything but public key material into allowed_signers
        if ! is_public_key_file "$SIGNING_PUB_PATH"; then
            print_warn "$SIGNING_PUB_PATH does not look like an SSH public key — refusing to add it to allowed_signers"
            return
        fi
        pub_key="$(cat "$SIGNING_PUB_PATH")"
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

# Append a directive line at global scope (top-level, or a "Host *" block at
# EOF) WITHOUT replacing any existing occurrence. Use this for multi-valued
# directives such as IdentityFile, where several lines are legitimate and the
# single-value replace logic of apply_single_ssh_directive would collapse them
# into one (re-introducing an agent-key lockout). ssh uses first-obtained-wins
# semantics, so appending keeps earlier host-specific/Host * settings
# authoritative.
append_ssh_directive() {
    local directive="$1"
    local value="$2"

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

    # Directive not set globally — append at EOF (single-value fill-the-gap).
    append_ssh_directive "$directive" "$value"
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

# Print the base64 key blobs (field 2) of every on-disk .pub file in ~/.ssh,
# one per line (data, stdout). Used to decide whether IdentitiesOnly has any
# file-based identity to fall back on.
list_disk_pub_blobs() {
    local f blob
    for f in "${SSH_DIR}"/*.pub; do
        [ -f "$f" ] || continue
        is_public_key_file "$f" || continue
        blob="$(awk 'NR==1{print $2}' "$f" 2>/dev/null || true)"
        [ -n "$blob" ] && printf '%s\n' "$blob"
    done
}

# True when at least one on-disk .pub stub carries the same key blob as a key
# held by a reachable agent. In that state IdentitiesOnly yes still offers the
# agent key (ssh matches the on-disk pubkey, then signs through the agent), so
# the guard does not need to write stubs.
ssh_pub_stubs_match_agent() {
    local disk_blobs agent_blob
    disk_blobs="$(list_disk_pub_blobs)"
    [ -n "$disk_blobs" ] || return 1
    while IFS= read -r agent_blob; do
        agent_blob="$(printf '%s' "$agent_blob" | awk '{print $2}')"
        [ -n "$agent_blob" ] || continue
        case "|$(printf '%s' "$disk_blobs" | tr '\n' '|')|" in
            *"|${agent_blob}|"*) return 0 ;;
        esac
    done <<EOF
$(list_modern_agent_keys)
EOF
    return 1
}

# Sanitize an SSH key comment into a safe filename stem: keep [A-Za-z0-9._-],
# collapse everything else to '_', trim leading/trailing '_'. Echoes nothing
# when the result is empty (caller falls back to a fingerprint-based name).
sanitize_stub_name() {
    local raw="$1"
    local out
    out="$(printf '%s' "$raw" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_')"
    # Collapse runs of underscores and trim them from the ends.
    out="$(printf '%s' "$out" | sed 's/__*/_/g; s/^_//; s/_$//')"
    printf '%s' "$out"
}

# Derive the .pub stub filename for an agent key line. Prefers a sanitized
# comment; falls back to agent_<fingerprint-prefix> when there is no usable
# comment. The fingerprint prefix is taken from ssh-keygen -lf (SHA256:...),
# itself sanitized, so the name is always filesystem-safe.
agent_key_stub_name() {
    local key="$1"
    local comment stem fp
    comment="$(printf '%s' "$key" | awk '{$1=""; $2=""; sub(/^[ \t]+/, ""); print}')"
    stem="$(sanitize_stub_name "$comment")"
    if [ -n "$stem" ]; then
        printf '%s' "$stem"
        return 0
    fi
    # Fallback: agent_<fingerprint-prefix>. Compute the fingerprint from the
    # literal public key via a temp file (ssh-keygen -lf needs a file).
    fp=""
    if command -v ssh-keygen >/dev/null 2>&1; then
        local tmp
        tmp="$(mktemp -t git-harden-stub.XXXXXX)"
        printf '%s\n' "$key" > "$tmp"
        fp="$(ssh-keygen -lf "$tmp" 2>/dev/null | awk '{print $2}' || true)"
        rm -f "$tmp"
    fi
    fp="$(sanitize_stub_name "$fp")"
    # Keep only a short prefix so names stay readable (strip the SHA256_ tag).
    fp="${fp#SHA256_}"
    fp="$(printf '%s' "$fp" | cut -c1-16)"
    if [ -n "$fp" ]; then
        printf 'agent_%s' "$fp"
    else
        printf 'agent_key'
    fi
}

# IdentitiesOnly guard (v0.7 3a). Returns 0 when "IdentitiesOnly yes" is SAFE to
# apply, 1 when it must be SKIPPED to avoid locking out an agent-only user.
#
# Safe when: a global IdentityFile already exists, OR an on-disk .pub stub
# matches an agent key, OR there are no agents holding keys at all (nothing to
# lock out — the existing algorithm/file path governs). When the user is
# agent-only with no matching stubs, offer to write PUBLIC-KEY stubs plus
# matching IdentityFile lines; decline (or -y mode) => skip with a warning.
identities_only_guard() {
    # An explicit global IdentityFile already gives IdentitiesOnly something to
    # offer — nothing to guard against.
    if [ -n "$(get_ssh_directive_value "IdentityFile")" ]; then
        return 0
    fi

    local agent_keys
    agent_keys="$(list_modern_agent_keys)"
    if [ -z "$agent_keys" ]; then
        # No agent keys to lock out. If there are also no on-disk stubs the user
        # has no global identities at all, but that is the pre-existing behavior
        # (algorithm/key-file path already governs); IdentitiesOnly is harmless.
        return 0
    fi

    # Agent keys exist. If an on-disk stub already matches one of them,
    # IdentitiesOnly yes keeps offering it.
    if ssh_pub_stubs_match_agent; then
        return 0
    fi

    # Agent-only with no matching stubs: applying IdentitiesOnly yes now would
    # stop the agent keys from being offered. Never silently lock out.
    print_warn "IdentitiesOnly yes would stop your agent-held key(s) from being offered — no matching IdentityFile or .pub stub exists"

    if [ "$AUTO_YES" = true ]; then
        print_info "Skipping IdentitiesOnly in -y mode (agent-only setup, no stubs). Re-run interactively to write public-key stubs."
        return 1
    fi

    printf '\n  Your keys live only in an SSH agent (e.g. 1Password/Bitwarden), with no\n' >&2
    printf '  IdentityFile on disk. IdentitiesOnly yes only offers keys named by an\n' >&2
    printf '  IdentityFile, so it would silently stop offering your agent keys.\n' >&2
    printf '  Writing PUBLIC-KEY stubs (~/.ssh/<name>.pub — public material only, no\n' >&2
    printf '  private key) plus matching IdentityFile lines keeps IdentitiesOnly\n' >&2
    printf '  working with the agent.\n\n' >&2

    if ! prompt_yn "Write public-key stubs + IdentityFile lines so IdentitiesOnly stays safe?" "y"; then
        print_warn "Skipping IdentitiesOnly yes — applying it now would lock out your agent keys"
        return 1
    fi

    # Write a .pub stub + IdentityFile line per agent key.
    local key stem stub_path priv_path written=0
    while IFS= read -r key; do
        [ -n "$key" ] || continue
        # Guard: only ever write PUBLIC material to disk.
        is_public_key_material "$key" || continue
        stem="$(agent_key_stub_name "$key")"
        stub_path="${SSH_DIR}/${stem}.pub"
        # Avoid clobbering an existing file; suffix until free.
        local n=1
        while [ -e "$stub_path" ]; do
            stub_path="${SSH_DIR}/${stem}_${n}.pub"
            n=$((n + 1))
        done
        printf '%s\n' "$key" > "$stub_path"
        chmod 600 "$stub_path"
        print_info "Wrote public-key stub $stub_path"
        # IdentityFile points at the private-key path (stub minus .pub), which is
        # how ssh names an identity; the agent supplies the private half.
        # APPEND (not replace) — multiple agent keys need multiple IdentityFile
        # lines; apply_single_ssh_directive would collapse them into one and
        # re-introduce the very lockout this guard prevents.
        priv_path="${stub_path%.pub}"
        append_ssh_directive "IdentityFile" "$priv_path"
        written=$((written + 1))
    done <<EOF
$agent_keys
EOF

    if (( written == 0 )); then
        print_warn "No public-key stubs written — skipping IdentitiesOnly yes to avoid a lockout"
        return 1
    fi

    print_info "Wrote ${written} public-key stub(s); IdentitiesOnly yes is now safe"
    return 0
}

# IdentityAgent offering (v0.7 3b). When a 1Password/Bitwarden socket is
# detected and SSH_AUTH_SOCK does not already point at it, offer a global
# IdentityAgent <socket> directive (append-at-EOF semantics). Never overwrites
# an existing IdentityAgent.
apply_identity_agent_offer() {
    # Respect any existing IdentityAgent — never overwrite the user's choice.
    if [ -n "$(get_ssh_directive_value "IdentityAgent")" ]; then
        return 0
    fi

    # Find the first 1Password/Bitwarden socket that SSH_AUTH_SOCK does not
    # already point at.
    local agent_type sock chosen=""
    while IFS=$'\t' read -r agent_type sock; do
        [ -n "$sock" ] || continue
        case "$agent_type" in
            1password|bitwarden) ;;
            *) continue ;;
        esac
        if [ "${SSH_AUTH_SOCK:-}" = "$sock" ]; then
            continue
        fi
        chosen="$sock"
        break
    done <<EOF
$(list_ssh_agent_sockets)
EOF

    [ -n "$chosen" ] || return 0

    printf '\n  %bIdentityAgent%b\n' "$BOLD" "$RESET" >&2
    printf '  A vault SSH agent socket was detected at:\n    %s\n' "$chosen" >&2
    printf '  SSH_AUTH_SOCK does not point at it. Setting IdentityAgent makes ssh use\n' >&2
    printf '  this agent for every host (vault keys with per-use approval prompts).\n\n' >&2

    if prompt_yn "Add global IdentityAgent ${chosen}?" "y"; then
        apply_single_ssh_directive "IdentityAgent" "$chosen"
        print_info "Applied IdentityAgent $chosen"
    fi
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

    # IdentitiesOnly is gated by a guard (v0.7 3a): applying it blindly can lock
    # out an agent-only user whose keys are not named by any IdentityFile/stub.
    # The guard may write public-key stubs (or skip the directive) before we get
    # here, so apply it separately from the always-safe AddKeysToAgent.
    apply_ssh_directive_group "Agent Convenience" \
        "AddKeysToAgent reduces passphrase fatigue so developers actually use
  passphrase-protected keys instead of disabling the passphrase." \
        "AddKeysToAgent"  "yes"  "Auto-add keys to ssh-agent after first use"

    # IdentityAgent (v0.7 3b): point ssh at a detected vault agent socket.
    apply_identity_agent_offer

    # IdentitiesOnly (v0.7 3a): only attempt when it is currently unset, and only
    # apply it when the guard confirms it will not lock out agent-held keys.
    if ssh_directive_needs_change "IdentitiesOnly" "yes"; then
        printf '\n  %bKey Offering (IdentitiesOnly)%b\n' "$BOLD" "$RESET" >&2
        printf '  Without IdentitiesOnly, ssh-agent offers ALL loaded keys to every server\n' >&2
        printf '  — a malicious server can enumerate which services you have access to.\n\n' >&2
        if identities_only_guard; then
            if prompt_yn "Apply IdentitiesOnly yes (only offer explicitly configured keys)?"; then
                apply_single_ssh_directive "IdentitiesOnly" "yes"
                print_info "Applied IdentitiesOnly yes"
            fi
        fi
    fi

    # ForwardAgent no as an applied global default (v0.7 3c). Forwarding lets any
    # root user on a host you connect to use your keys for the session.
    if ssh_directive_needs_change "ForwardAgent" "no"; then
        printf '\n  %bForwardAgent%b\n' "$BOLD" "$RESET" >&2
        printf '  Setting ForwardAgent no globally stops your agent being forwarded by\n' >&2
        printf '  default. Override per-host with "ForwardAgent yes" inside a Host block,\n' >&2
        printf '  and prefer a confirmation-prompting agent (1Password, ssh-add -c) when\n' >&2
        printf '  forwarding is unavoidable.\n\n' >&2
        if prompt_yn "Apply ForwardAgent no globally (per-host override stays possible)?"; then
            apply_single_ssh_directive "ForwardAgent" "no"
            print_info "Applied ForwardAgent no"
        fi
    fi

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

    if [ "$MIGRATE" = true ]; then
        # Migration is interactive only and never runs under -y (AC-2).
        if [ "$AUTO_YES" = true ]; then
            die "--migrate is interactive only and cannot be combined with -y."
        fi
        run_migration
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
    audit_secret_inventory
    # FR4 advisor runs after the inventory in both --audit and apply phases
    # (the audit always precedes apply, so a single call here covers both). It
    # prints nothing when the inventory found no credentials.
    secret_advisor
    audit_signing
    audit_ssh_config
    audit_ssh_agents
    audit_ssh_key_hygiene
    audit_ssh_private_keys

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
    apply_secret_permissions
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
