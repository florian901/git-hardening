#!/usr/bin/env bash
# git-harden.sh — Audit and harden global git configuration
# Usage: git-harden.sh [--audit] [-y] [--help]

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
readonly VERSION="1.0.0"
readonly BACKUP_DIR="${HOME}/.config/git"
readonly HOOKS_DIR="${HOME}/.config/git/hooks"
readonly ALLOWED_SIGNERS_FILE="${HOME}/.config/git/allowed_signers"
readonly SSH_DIR="${HOME}/.ssh"
readonly SSH_CONFIG="${SSH_DIR}/config"

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
PLATFORM=""

# Audit counters
AUDIT_OK=0
AUDIT_WARN=0
AUDIT_MISS=0

# Whether signing key was found
SIGNING_KEY_FOUND=false
export SIGNING_KEY_PATH="" # private key path; exported for hook/subshell use
SIGNING_PUB_PATH=""

# Credential helper detected for this platform
DETECTED_CRED_HELPER=""

# Optional tool availability
HAS_YKMAN=false
HAS_FIDO2_TOKEN=false

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

print_ok() {
    printf '%b[OK]%b   %s\n' "$GREEN" "$RESET" "$1" >&2
    AUDIT_OK=$((AUDIT_OK + 1))
}

print_warn() {
    printf '%b[WARN]%b %s\n' "$YELLOW" "$RESET" "$1" >&2
    AUDIT_WARN=$((AUDIT_WARN + 1))
}

print_miss() {
    printf '%b[MISS]%b %s\n' "$RED" "$RESET" "$1" >&2
    AUDIT_MISS=$((AUDIT_MISS + 1))
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
  --audit       Run audit only (no changes), exit 0 if all OK, 2 if issues found
  -y, --yes     Auto-apply all recommended settings (no prompts)
  --help, -h    Show this help message
  --version     Show version

Exit codes:
  0  All settings OK, or changes successfully applied
  1  Error (missing dependencies, etc.)
  2  Audit found issues (--audit mode only)
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

detect_credential_helper() {
    case "$PLATFORM" in
        macos)
            DETECTED_CRED_HELPER="osxkeychain"
            ;;
        linux)
            # Try to find libsecret credential helper
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
            else
                DETECTED_CRED_HELPER="cache --timeout=3600"
            fi
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
    print_header "Object Integrity"
    audit_git_setting "transfer.fsckObjects" "true"
    audit_git_setting "fetch.fsckObjects" "true"
    audit_git_setting "receive.fsckObjects" "true"

    print_header "Protocol Restrictions"
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

    print_header "Hook Control"
    # shellcheck disable=SC2088 # Intentional: git config stores literal ~
    audit_git_setting "core.hooksPath" "~/.config/git/hooks"

    print_header "Repository Safety"
    audit_git_setting "safe.bareRepository" "explicit"
    audit_git_setting "submodule.recurse" "false"

    print_header "Pull/Merge Hardening"
    audit_git_setting "pull.ff" "only"
    audit_git_setting "merge.ff" "only"

    # AC-15: warn if pull.rebase is set (conflicts with pull.ff=only)
    local pull_rebase
    pull_rebase="$(git config --global --get pull.rebase 2>/dev/null || true)"
    if [ -n "$pull_rebase" ]; then
        print_warn "pull.rebase = $pull_rebase (conflicts with pull.ff=only — consider unsetting)"
    fi

    print_header "Transport Security"
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

    audit_git_setting "http.sslVerify" "true"

    print_header "Credential Storage"
    local cred_current
    cred_current="$(git config --global --get credential.helper 2>/dev/null || true)"
    if [ -z "$cred_current" ]; then
        print_miss "credential.helper (expected: $DETECTED_CRED_HELPER)"
    elif [ "$cred_current" = "store" ]; then
        print_warn "credential.helper = store (INSECURE: stores passwords in plaintext; expected: $DETECTED_CRED_HELPER)"
    elif [ "$cred_current" = "$DETECTED_CRED_HELPER" ]; then
        print_ok "credential.helper = $cred_current"
    else
        # Non-store, non-recommended — could be user's custom helper
        print_warn "credential.helper = $cred_current (expected: $DETECTED_CRED_HELPER)"
    fi

    print_header "Visibility"
    audit_git_setting "log.showSignature" "true"
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

    local current
    current="$(grep -i "^[[:space:]]*${directive}[[:space:]]" "$SSH_CONFIG" 2>/dev/null | head -1 | sed 's/^[[:space:]]*[^ ]*[[:space:]]*//' || true)"
    current="$(strip_ssh_value "$current")"

    if [ -z "$current" ]; then
        print_miss "SSH: $directive (expected: $expected)"
    elif [ "$current" = "$expected" ]; then
        print_ok "SSH: $directive = $current"
    else
        print_warn "SSH: $directive = $current (expected: $expected)"
    fi
}

audit_ssh_config() {
    print_header "SSH Configuration"

    if [ ! -f "$SSH_CONFIG" ]; then
        print_miss "$SSH_CONFIG does not exist"
        return
    fi

    audit_ssh_directive "StrictHostKeyChecking" "accept-new"
    audit_ssh_directive "HashKnownHosts" "yes"
    audit_ssh_directive "IdentitiesOnly" "yes"
    audit_ssh_directive "AddKeysToAgent" "yes"
    audit_ssh_directive "PubkeyAcceptedAlgorithms" "ssh-ed25519,sk-ssh-ed25519@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com"
}

print_audit_report() {
    print_header "Audit Summary"
    printf '%b  %d OK  /  %d WARN  /  %d MISS%b\n' \
        "$BOLD" "$AUDIT_OK" "$AUDIT_WARN" "$AUDIT_MISS" "$RESET" >&2

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

apply_git_setting() {
    local key="$1"
    local value="$2"
    local label="${3:-$key}"

    local current
    current="$(git config --global --get "$key" 2>/dev/null || true)"

    if [ "$current" = "$value" ]; then
        return 0
    fi

    if prompt_yn "Set $label = $value?"; then
        git config --global "$key" "$value"
        print_info "Set $label = $value"
    fi
}

apply_git_config() {
    print_header "Applying Git Config Hardening"

    # Object integrity
    apply_git_setting "transfer.fsckObjects" "true"
    apply_git_setting "fetch.fsckObjects" "true"
    apply_git_setting "receive.fsckObjects" "true"

    # Protocol restrictions
    apply_git_setting "protocol.allow" "never"
    apply_git_setting "protocol.https.allow" "always"
    apply_git_setting "protocol.ssh.allow" "always"
    apply_git_setting "protocol.file.allow" "user"
    apply_git_setting "protocol.git.allow" "never"
    apply_git_setting "protocol.ext.allow" "never"

    # Filesystem protection
    apply_git_setting "core.protectNTFS" "true"
    apply_git_setting "core.protectHFS" "true"
    apply_git_setting "core.fsmonitor" "false"

    # Hook control
    mkdir -p "$HOOKS_DIR"
    # shellcheck disable=SC2088 # Intentional: git config stores literal ~
    apply_git_setting "core.hooksPath" "~/.config/git/hooks"

    # Repository safety
    apply_git_setting "safe.bareRepository" "explicit"
    apply_git_setting "submodule.recurse" "false"

    # Pull/merge hardening
    apply_git_setting "pull.ff" "only"
    apply_git_setting "merge.ff" "only"

    # Transport security
    local instead_of
    instead_of="$(git config --global --get 'url.https://.insteadOf' 2>/dev/null || true)"
    if [ "$instead_of" != "http://" ]; then
        if prompt_yn "Set url.\"https://\".insteadOf = http://?"; then
            git config --global 'url.https://.insteadOf' 'http://'
            print_info "Set url.\"https://\".insteadOf = http://"
        fi
    fi

    apply_git_setting "http.sslVerify" "true"

    # Credential storage
    local cred_current
    cred_current="$(git config --global --get credential.helper 2>/dev/null || true)"
    if [ "$cred_current" != "$DETECTED_CRED_HELPER" ]; then
        local cred_prompt="Set credential.helper = $DETECTED_CRED_HELPER?"
        if [ "$cred_current" = "store" ]; then
            cred_prompt="Replace INSECURE credential.helper=store with $DETECTED_CRED_HELPER?"
        fi
        if prompt_yn "$cred_prompt"; then
            git config --global credential.helper "$DETECTED_CRED_HELPER"
            print_info "Set credential.helper = $DETECTED_CRED_HELPER"
        fi
    fi

    # Visibility
    apply_git_setting "log.showSignature" "true"
}

apply_signing_config() {
    print_header "Signing Configuration"

    # Always safe to set format and allowed signers
    apply_git_setting "gpg.format" "ssh"
    # shellcheck disable=SC2088 # Intentional: git config stores literal ~
    apply_git_setting "gpg.ssh.allowedSignersFile" "~/.config/git/allowed_signers"

    # Detect existing signing key
    detect_existing_keys

    if [ "$AUTO_YES" = true ]; then
        # In -y mode: only enable signing if key exists
        if [ "$SIGNING_KEY_FOUND" = true ] && [ -n "$SIGNING_PUB_PATH" ] && [ -f "$SIGNING_PUB_PATH" ]; then
            git config --global user.signingkey "$SIGNING_PUB_PATH"
            print_info "Set user.signingkey = $SIGNING_PUB_PATH"
            apply_git_setting "commit.gpgsign" "true"
            apply_git_setting "tag.gpgsign" "true"
            apply_git_setting "tag.forceSignAnnotated" "true"
            setup_allowed_signers
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
    SIGNING_KEY_PATH=""
    SIGNING_PUB_PATH=""

    # Check if a signing key is already configured
    local configured_key
    configured_key="$(git config --global --get user.signingkey 2>/dev/null || true)"
    if [ -n "$configured_key" ]; then
        local expanded_key
        expanded_key="${configured_key/#\~/$HOME}"
        if [ -f "$expanded_key" ]; then
            SIGNING_KEY_FOUND=true
            SIGNING_PUB_PATH="$expanded_key"
            # Derive private key path (remove .pub suffix if present)
            SIGNING_KEY_PATH="${expanded_key%.pub}"
            return
        fi
    fi

    # Check common ed25519 key locations (sk first, then software)
    local priv_path pub_path
    for key_type in id_ed25519_sk id_ed25519; do
        priv_path="${SSH_DIR}/${key_type}"
        pub_path="${priv_path}.pub"
        if [ -f "$pub_path" ]; then
            SIGNING_KEY_FOUND=true
            SIGNING_KEY_PATH="$priv_path"
            SIGNING_PUB_PATH="$pub_path"
            return
        fi
    done

    # Check IdentityFile directives in ~/.ssh/config for custom-named keys
    if [ -f "$SSH_CONFIG" ]; then
        local identity_path
        while IFS= read -r identity_path; do
            # Strip inline comments and quotes
            identity_path="$(strip_ssh_value "$identity_path")"
            [ -z "$identity_path" ] && continue
            # Expand tilde safely
            identity_path="${identity_path/#\~/$HOME}"

            pub_path="${identity_path}.pub"
            if [ -f "$pub_path" ]; then
                # Only use ed25519 or ed25519-sk keys for signing
                local key_type_str
                key_type_str="$(head -1 "$pub_path" 2>/dev/null || true)"
                case "$key_type_str" in
                    ssh-ed25519*|sk-ssh-ed25519*)
                        SIGNING_KEY_FOUND=true
                        SIGNING_KEY_PATH="$identity_path"
                        SIGNING_PUB_PATH="$pub_path"
                        return
                        ;;
                esac
            fi
        done <<EOF
$(grep -i '^[[:space:]]*IdentityFile[[:space:]]' "$SSH_CONFIG" 2>/dev/null | sed 's/^[[:space:]]*[Ii][Dd][Ee][Nn][Tt][Ii][Tt][Yy][Ff][Ii][Ll][Ee][[:space:]]*//')
EOF
    fi
}

detect_fido2_hardware() {
    if [ "$HAS_YKMAN" = true ]; then
        if ykman info >/dev/null 2>&1; then
            return 0
        fi
    fi
    if [ "$HAS_FIDO2_TOKEN" = true ]; then
        if fido2-token -L 2>/dev/null | grep -q .; then
            return 0
        fi
    fi
    return 1
}

signing_wizard() {
    print_header "SSH Signing Setup Wizard"

    if [ "$SIGNING_KEY_FOUND" = true ]; then
        printf '  Found existing key: %s\n' "$SIGNING_PUB_PATH" >&2
        if prompt_yn "Use this key for git signing?"; then
            git config --global user.signingkey "$SIGNING_PUB_PATH"
            print_info "Set user.signingkey = $SIGNING_PUB_PATH"
            apply_git_setting "commit.gpgsign" "true"
            apply_git_setting "tag.gpgsign" "true"
            apply_git_setting "tag.forceSignAnnotated" "true"
            setup_allowed_signers
            return
        fi
    fi

    # Offer key generation options
    local has_fido2=false
    if detect_fido2_hardware; then
        has_fido2=true
    fi

    printf '\n  Signing key options:\n' >&2
    printf '    1) Generate a new ed25519 SSH key (software)\n' >&2
    if [ "$has_fido2" = true ]; then
        printf '    2) Generate a new ed25519-sk SSH key (FIDO2 hardware key)\n' >&2
    fi
    printf '    s) Skip signing setup\n' >&2

    local choice
    printf '\n  Choose [1%s/s]: ' "$(if [ "$has_fido2" = true ]; then printf '/2'; fi)" >&2
    read -r choice </dev/tty || choice="s"

    case "$choice" in
        1)
            generate_ssh_key
            ;;
        2)
            if [ "$has_fido2" = true ]; then
                generate_fido2_key
            else
                print_warn "FIDO2 not available. Skipping."
                return
            fi
            ;;
        *)
            print_info "Skipping signing setup."
            return
            ;;
    esac

    if [ "$SIGNING_KEY_FOUND" = true ]; then
        git config --global user.signingkey "$SIGNING_PUB_PATH"
        print_info "Set user.signingkey = $SIGNING_PUB_PATH"
        apply_git_setting "commit.gpgsign" "true"
        apply_git_setting "tag.gpgsign" "true"
        apply_git_setting "tag.forceSignAnnotated" "true"
        setup_allowed_signers
    fi
}

generate_ssh_key() {
    local key_path="${SSH_DIR}/id_ed25519"

    if [ -f "$key_path" ]; then
        print_warn "$key_path already exists. Not overwriting."
        SIGNING_KEY_FOUND=true
        SIGNING_KEY_PATH="$key_path"
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
        SIGNING_KEY_PATH="$key_path"
        SIGNING_PUB_PATH="${key_path}.pub"
        print_info "Key generated: ${key_path}.pub"
    else
        print_warn "Key generation may have failed — ${key_path}.pub not found"
    fi
}

generate_fido2_key() {
    local key_path="${SSH_DIR}/id_ed25519_sk"

    if [ -f "$key_path" ]; then
        print_warn "$key_path already exists. Not overwriting."
        SIGNING_KEY_FOUND=true
        SIGNING_KEY_PATH="$key_path"
        SIGNING_PUB_PATH="${key_path}.pub"
        return
    fi

    printf '  Generating ed25519-sk SSH key (touch your security key when prompted)...\n' >&2

    local email
    email="$(git config --global --get user.email 2>/dev/null || true)"
    if [ -z "$email" ]; then
        printf '  Enter email for key comment: ' >&2
        read -r email </dev/tty || email="git-signing"
    fi

    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"

    # Do NOT suppress stderr — per AC-7
    ssh-keygen -t ed25519-sk -C "$email" -f "$key_path" </dev/tty

    if [ -f "${key_path}.pub" ]; then
        SIGNING_KEY_FOUND=true
        SIGNING_KEY_PATH="$key_path"
        SIGNING_PUB_PATH="${key_path}.pub"
        print_info "Key generated: ${key_path}.pub"
    else
        print_warn "Key generation may have failed — ${key_path}.pub not found"
    fi
}

setup_allowed_signers() {
    if [ -z "$SIGNING_PUB_PATH" ] || [ ! -f "$SIGNING_PUB_PATH" ]; then
        return
    fi

    local email
    email="$(git config --global --get user.email 2>/dev/null || true)"
    if [ -z "$email" ]; then
        print_warn "user.email not set — cannot create allowed_signers entry"
        return
    fi

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

apply_ssh_directive() {
    local directive="$1"
    local value="$2"

    # Check if directive already exists with correct value (case-insensitive directive match)
    local current
    current="$(grep -i "^[[:space:]]*${directive}[[:space:]]" "$SSH_CONFIG" 2>/dev/null | head -1 | sed 's/^[[:space:]]*[^ ]*[[:space:]]*//' || true)"
    current="$(strip_ssh_value "$current")"

    if [ "$current" = "$value" ]; then
        return
    fi

    if [ -n "$current" ]; then
        # Directive exists but with wrong value
        if prompt_yn "Update SSH directive: $directive $current -> $value?"; then
            # Use temp file to avoid sed -i portability issues
            local tmpfile
            tmpfile="$(mktemp "${SSH_CONFIG}.XXXXXX")"
            # Replace first occurrence of the directive (case-insensitive)
            local replaced=false
            while IFS= read -r line || [ -n "$line" ]; do
                if [ "$replaced" = false ] && printf '%s' "$line" | grep -qi "^[[:space:]]*${directive}[[:space:]]"; then
                    printf '%s %s\n' "$directive" "$value"
                    replaced=true
                else
                    printf '%s\n' "$line"
                fi
            done < "$SSH_CONFIG" > "$tmpfile"
            mv "$tmpfile" "$SSH_CONFIG"
            chmod 600 "$SSH_CONFIG"
            print_info "Updated $directive = $value in $SSH_CONFIG"
        fi
    else
        # Directive missing entirely
        if prompt_yn "Add SSH directive: $directive $value?"; then
            printf '%s %s\n' "$directive" "$value" >> "$SSH_CONFIG"
            print_info "Added $directive $value to $SSH_CONFIG"
        fi
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
    fi

    apply_ssh_directive "StrictHostKeyChecking" "accept-new"
    apply_ssh_directive "HashKnownHosts" "yes"
    apply_ssh_directive "IdentitiesOnly" "yes"
    apply_ssh_directive "AddKeysToAgent" "yes"
    apply_ssh_directive "PubkeyAcceptedAlgorithms" "ssh-ed25519,sk-ssh-ed25519@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com"
}

# ------------------------------------------------------------------------------
# Admin recommendations
# ------------------------------------------------------------------------------

print_admin_recommendations() {
    print_header "Admin / Org-Level Recommendations"
    printf '  These are informational and cannot be applied by this script:\n\n' >&2
    printf '  • Enable branch protection rules on main/master branches\n' >&2
    printf '  • Enable GitHub vigilant mode (Settings → SSH and GPG keys → Flag unsigned commits)\n' >&2
    printf '  • Restrict force-pushes (disable or limit to admins)\n' >&2
    printf '  • Rotate personal access tokens regularly; prefer fine-grained tokens\n' >&2
    printf '  • Use short-lived credentials (GitHub App tokens, OIDC) in CI/CD\n' >&2
    printf '  • Require signed commits via branch protection (Require signed commits)\n' >&2
    printf '  • Audit deploy keys and service account access quarterly\n' >&2
    printf '  • If using hook frameworks (husky, lefthook, pre-commit), pin versions and review changes\n' >&2
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

    if ! prompt_yn "Have you reviewed this script (or had an AI assistant review it) for safety?"; then
        printf '\n  You can review this script by piping it to an AI coding assistant:\n\n' >&2
        printf '  %bClaude Code:%b\n' "$BOLD" "$RESET" >&2
        printf '    cat "%s" | claude "Review this shell script for security issues.\n' "$script_path" >&2
        printf '    Check that it only modifies git and SSH config, makes no network\n' >&2
        printf '    calls, and does not exfiltrate data. List every file it writes to."\n\n' >&2
        printf '  %bGemini CLI:%b\n' "$BOLD" "$RESET" >&2
        printf '    cat "%s" | gemini "Review this shell script for security issues.\n' "$script_path" >&2
        printf '    Check that it only modifies git and SSH config, makes no network\n' >&2
        printf '    calls, and does not exfiltrate data. List every file it writes to."\n\n' >&2
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

    # --- Audit phase ---
    AUDIT_OK=0
    AUDIT_WARN=0
    AUDIT_MISS=0

    audit_git_config
    audit_signing
    audit_ssh_config

    local audit_exit=0
    print_audit_report || audit_exit=$?

    if [ "$AUDIT_ONLY" = true ]; then
        exit "$audit_exit"
    fi

    # If everything is already OK, nothing to do
    if [ "$audit_exit" -eq 0 ]; then
        print_info "All settings already match recommendations. Nothing to do."
        print_admin_recommendations
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
    apply_signing_config
    apply_ssh_config
    print_admin_recommendations

    print_info "Hardening complete. Re-run with --audit to verify."
}

main "$@"
