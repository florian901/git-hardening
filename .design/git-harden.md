# Feature: git-harden.sh

## Summary
A single-file bash script that audits and hardens a developer's global git configuration with security-focused defaults. It runs an audit-first flow (color-coded report of current state), then interactively applies recommended settings covering object integrity, protocol restrictions, filesystem protection, hook control, SSH signing with FIDO2 support, SSH transport hardening, and credential security. A `-y` flag auto-applies all defaults, and `--audit` exits after the report for CI use.

## Requirements
- REQ-1: The script must audit all git global config settings listed in the Architecture section and report each as `[OK]` (matches recommended), `[WARN]` (set to non-recommended value), or `[MISS]` (not configured), with color-coded output to stderr.
- REQ-2: The script must apply hardening settings via `git config --global` in interactive mode (prompt per setting, default Y) or auto-apply mode (`-y`).
- REQ-3: The script must back up the current global git config to `~/.config/git/pre-harden-backup-<timestamp>.txt` before making any changes.
- REQ-4: The script must detect the platform (macOS/Linux) and select the appropriate credential helper (`osxkeychain` on macOS, `libsecret` or `cache` on Linux).
- REQ-5: The script must provide an SSH signing setup wizard with two tiers: software SSH key (`ed25519`) and FIDO2 hardware key (`ed25519-sk`), detecting existing keys and hardware automatically.
- REQ-6: In `-y` mode, signing must only be enabled (`commit.gpgsign`, `tag.gpgsign`) if a valid signing key is detected and its public key file is readable. If no key exists, only non-breaking settings (`gpg.format`, `gpg.ssh.allowedSignersFile`) are configured.
- REQ-7: The script must audit and optionally harden `~/.ssh/config` with secure defaults (`StrictHostKeyChecking accept-new`, `HashKnownHosts yes`, `IdentitiesOnly yes`, `AddKeysToAgent yes`, modern `PubkeyAcceptedAlgorithms`).
- REQ-8: The script must print admin/org-level recommendations (branch protection, vigilant mode, force-push policy, token hygiene) as informational output without applying changes.
- REQ-9: The script must be compatible with Bash 3.2 (macOS default). No associative arrays, no `mapfile`/`readarray`, no `${var,,}` case conversion, no `declare -A`.
- REQ-10: The script must be idempotent — re-running it on an already-hardened system changes nothing.
- REQ-11: Exit codes must be: 0 (all OK or changes applied), 1 (error), 2 (audit found issues).
- REQ-12: The script must pass `shellcheck` with no errors or warnings.

## Acceptance Criteria
- [ ] AC-1: Running `git-harden.sh --audit` on a fresh git config prints a report with `[MISS]` for all 20+ hardening settings and exits with code 2.
- [ ] AC-2: Running `git-harden.sh -y` on a fresh config applies all settings; a subsequent `--audit` exits with code 0 (all `[OK]`).
- [ ] AC-3: Running `git-harden.sh -y` twice produces identical git config output (idempotent).
- [ ] AC-4: On macOS, `credential.helper` is set to `osxkeychain`. On Linux with libsecret available, it uses the detected libsecret path; otherwise `cache --timeout=3600`.
- [ ] AC-5: If `credential.helper` is currently `store`, the audit reports `[WARN]` and interactive mode offers to replace it.
- [ ] AC-6: The signing wizard detects existing `~/.ssh/id_ed25519` and offers to use it as signing key.
- [ ] AC-7: If a FIDO2 device is detected (via `ykman info` or `fido2-token -L`), the wizard offers Tier 2 (generate `ed25519-sk` key). The `ssh-keygen` stderr is not suppressed.
- [ ] AC-8: In `-y` mode with no SSH key present, `commit.gpgsign` and `tag.gpgsign` are NOT set. A note is printed directing the user to run interactively.
- [ ] AC-9: `~/.config/git/hooks/` directory is created if missing. `core.hooksPath` is set with literal `~` (not expanded).
- [ ] AC-10: `~/.ssh/config` is created with mode `600` (and `~/.ssh/` with mode `700`) if they don't exist. SSH directives are only appended if not already present.
- [ ] AC-11: The script runs without error on Bash 3.2.57 (macOS default) and Bash 5.x (Linux).
- [ ] AC-12: `shellcheck git-harden.sh` produces zero errors and zero warnings.
- [ ] AC-13: A config backup file is created at `~/.config/git/pre-harden-backup-<timestamp>.txt` before any changes are made.
- [ ] AC-14: `protocol.allow` is set to `never`; only `https`, `ssh`, and `file` (as `user`) are whitelisted. `git://` and `ext://` are explicitly blocked.
- [ ] AC-15: If `pull.rebase` is currently set, the audit phase reports a `[WARN]` about the conflict with `pull.ff=only`.

## Architecture

The script is a single file `git-harden.sh` at the repo root, using `#!/usr/bin/env bash` with strict mode (`set -o errexit`, `set -o nounset`, `set -o pipefail`, `IFS=$'\n\t'`).

### Internal structure (functions)

All variables inside functions use `local`. Global constants use `readonly UPPER_CASE`. The script follows the conventions in `AGENTS.md` (Shell Script Development Standards v2.0).

**Entry point and argument parsing:**
- `main()` — orchestrates the full flow: preflight, audit, apply, recommendations
- `parse_args()` — handles `-y`, `--audit`, `--help` flags
- `die()` — fatal error handler (prints to stderr, exits 1)

**Platform detection:**
- `detect_platform()` — sets `PLATFORM` to `macos` or `linux` via `uname -s`
- `check_dependencies()` — verifies `git` >= 2.34.0, `ssh-keygen` present; detects optional tools (`ykman`, `fido2-token`, credential helpers)

**Audit functions (read-only, no side effects):**
- `audit_git_config()` — checks each hardening setting against `git config --global --get`
- `audit_ssh_config()` — checks `~/.ssh/config` for recommended directives
- `audit_signing()` — checks signing config and key availability
- `print_audit_report()` — renders the color-coded report to stderr

**Apply functions (write operations):**
- `apply_git_config()` — sets each non-OK setting via `git config --global`
- `apply_ssh_config()` — appends missing directives to `~/.ssh/config`
- `signing_wizard()` — interactive signing setup (tier selection, key generation/detection)
- `detect_existing_keys()` — scans `~/.ssh/` and `~/.ssh/config` IdentityFile directives
- `detect_fido2_hardware()` — checks `ykman info` and `fido2-token -L`
- `generate_ssh_key()` — wraps `ssh-keygen -t ed25519`
- `generate_fido2_key()` — wraps `ssh-keygen -t ed25519-sk` with touch prompt
- `setup_allowed_signers()` — creates/updates `~/.config/git/allowed_signers`
- `print_admin_recommendations()` — prints org-level advice to stderr

**Helpers:**
- `prompt_yn()` — prompt with configurable default, respects `-y` mode
- `print_ok()`, `print_warn()`, `print_miss()` — color-coded status output to stderr

### Git config settings applied

**Object integrity:** `transfer.fsckObjects=true`, `fetch.fsckObjects=true`, `receive.fsckObjects=true`

**Protocol restrictions (default deny):** `protocol.allow=never`, `protocol.https.allow=always`, `protocol.ssh.allow=always`, `protocol.file.allow=user`, `protocol.git.allow=never`, `protocol.ext.allow=never`

**Filesystem protection:** `core.protectNTFS=true`, `core.protectHFS=true`, `core.fsmonitor=false`

**Hook control:** `core.hooksPath=~/.config/git/hooks`

**Repository safety:** `safe.bareRepository=explicit`, `submodule.recurse=false`

**Pull/merge hardening:** `pull.ff=only`, `merge.ff=only`

**Transport security:** `url."https://".insteadOf=http://`, `http.sslVerify=true`

**Credential storage:** `credential.helper` (platform-detected)

**Signing:** `gpg.format=ssh`, `user.signingkey` (detected), `commit.gpgsign=true`, `tag.gpgsign=true`, `tag.forceSignAnnotated=true`, `gpg.ssh.allowedSignersFile=~/.config/git/allowed_signers`

**Visibility:** `log.showSignature=true`

**Optional (interactive only):** `core.symlinks=false`, `merge.verifySignatures=true`

### SSH config directives appended to `~/.ssh/config`

`StrictHostKeyChecking accept-new`, `HashKnownHosts yes`, `IdentitiesOnly yes`, `AddKeysToAgent yes`, `PubkeyAcceptedAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com`

### Dependencies

**Required:** `git` >= 2.34.0, `ssh-keygen`
**Optional:** `ykman` or `fido2-token` (FIDO2 detection), OS keychain (`osxkeychain` on macOS, `libsecret` on Linux)

## Open Questions

No unresolved questions remain. All design decisions have been validated through brainstorming, research, spec review, and external review.

## Out of Scope
- GPG signing support — SSH signing covers the same use cases with far less complexity
- Server-side changes — the script only modifies the developer's local config
- Undo/restore command — the script is idempotent; devs can manually unset any setting with `git config --global --unset`
- Windows/WSL support
- Per-repo config modification — global config only
- jj support
- Hook dispatcher scripts for projects using husky/lefthook/pre-commit — mentioned in admin recommendations but not implemented
