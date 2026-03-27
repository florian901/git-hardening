# git-harden.sh — Design Spec

## Purpose

A single-file shell script that audits and hardens a developer's global git configuration with security-focused defaults. Protects against history rewriting, supply chain attacks, credential theft, and malicious repository exploitation.

## Target Audience

Individual developers on macOS and Linux. The script also prints server/org-level recommendations but does not apply them.

## Invocation

```
git-harden.sh            # audit report → interactive apply
git-harden.sh -y         # audit report → auto-apply all recommended defaults
git-harden.sh --audit    # audit report only, no changes
git-harden.sh --help     # usage info
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All settings OK, or changes applied successfully |
| 1 | Error (missing dependencies, write failure, etc.) |
| 2 | Audit found issues (useful for CI/onboarding checks). Missing signing key counts as an issue. |

## Compatibility

- Shebang: `#!/usr/bin/env bash`. The script targets bash on both macOS and Linux. It does not need to run under zsh natively, but works when invoked from a zsh session via `bash git-harden.sh` or `./git-harden.sh`.
- **Bash 3.2 compatible** — macOS ships Bash 3.2 (GPLv2). No associative arrays, no `mapfile`/`readarray`, no `${var,,}` case conversion, no `&>>`/`|&` redirection, no `declare -A`. Use indexed arrays and `tr '[:upper:]' '[:lower:]'` for case conversion.
- macOS and Linux, with platform detection for credential helpers and tool paths
- Idempotent — safe to re-run; already-correct settings are left untouched

## Flow

```
1. Preflight checks
   ├── Detect platform (macOS / Linux)
   ├── Check git version (require 2.34+ for SSH signing)
   ├── Check ssh-keygen availability
   ├── Detect FIDO2 hardware (ykman or fido2-token)
   └── Detect existing SSH keys and FIDO2 keys

2. Audit phase
   ├── Read current git config --global for each hardening setting
   ├── Print color-coded report:
   │   [OK]   green  — already set to recommended value
   │   [WARN] yellow — set to a non-recommended value
   │   [MISS] red    — not configured
   └── If --audit flag: print report and exit (code 0 or 2)

3. Apply phase (interactive or -y)
   ├── Back up current config: git config --global --list > ~/.config/git/pre-harden-backup-<timestamp>.txt
   ├── For each non-OK setting:
   │   ├── Interactive: show description, current vs recommended, prompt [Y/n]
   │   └── -y mode: apply silently
   ├── Create ~/.config/git/hooks/ directory if needed
   ├── Signing setup wizard (see below)
   └── Print summary of changes made

4. Admin recommendations
   └── Print informational section (no changes applied)
```

## Settings

### Object Integrity

| Setting | Value | Rationale |
|---------|-------|-----------|
| `transfer.fsckObjects` | `true` | Validate all transferred objects — catches corruption and malicious payloads |
| `fetch.fsckObjects` | `true` | Validate on fetch specifically |
| `receive.fsckObjects` | `true` | Validate on receive specifically |

### Protocol Restrictions (Default Deny)

| Setting | Value | Rationale |
|---------|-------|-----------|
| `protocol.allow` | `never` | Block all protocols by default |
| `protocol.https.allow` | `always` | Whitelist HTTPS |
| `protocol.ssh.allow` | `always` | Whitelist SSH |
| `protocol.file.allow` | `user` | Allow local file protocol only when user-initiated (not from submodules/redirects) |
| `protocol.git.allow` | `never` | Block git:// — unauthenticated, unencrypted, MitM-able |
| `protocol.ext.allow` | `never` | Block ext:// — allows arbitrary command execution via submodule URLs |

### Filesystem Protection

| Setting | Value | Rationale |
|---------|-------|-----------|
| `core.protectNTFS` | `true` | Block NTFS alternate data stream attacks; protects cross-platform collaborators even on macOS/Linux |
| `core.protectHFS` | `true` | Block HFS+ Unicode normalization tricks (invisible chars creating `.git` variants) |
| `core.fsmonitor` | `false` | Prevent fsmonitor-based code execution from repo-local config |

### Hook Execution Control

| Setting | Value | Rationale |
|---------|-------|-----------|
| `core.hooksPath` | `~/.config/git/hooks` | Redirect hooks to user-controlled directory; repo-local `.git/hooks/` are never executed. The script creates this directory if it doesn't exist. The literal tilde `~` is stored in config (not expanded) so dotfile portability is preserved. |

### Repository Safety

| Setting | Value | Rationale |
|---------|-------|-----------|
| `safe.bareRepository` | `explicit` | Prevent auto-detection of bare repos in unexpected locations (CVE-2024-32465) |
| `submodule.recurse` | `false` | Prevent automatic submodule operations during pull, checkout, and fetch. For clone, users should also use `--no-recurse-submodules` (noted in admin recommendations). |

### Pull & Merge Hardening

| Setting | Value | Rationale |
|---------|-------|-----------|
| `pull.ff` | `only` | Refuse non-fast-forward pulls — surfaces rewritten history. **Note:** overrides any existing `pull.rebase` setting. The audit phase checks for `pull.rebase` and warns about the conflict. |
| `merge.ff` | `only` | Same protection for explicit merges |

### Transport Security

| Setting | Value | Rationale |
|---------|-------|-----------|
| `url."https://".insteadOf` | `http://` | Transparently upgrade HTTP to HTTPS |
| `http.sslVerify` | `true` | Explicitly set; prevents repo-level overrides disabling TLS verification |

### Credential Storage

Platform-detected:

| Platform | Setting | Value |
|----------|---------|-------|
| macOS | `credential.helper` | `osxkeychain` |
| Linux (libsecret available) | `credential.helper` | Detected by checking common paths: `/usr/lib/git-core/git-credential-libsecret`, `/usr/libexec/git-core/git-credential-libsecret` |
| Linux (fallback) | `credential.helper` | `cache --timeout=3600` |

Detection: check if the libsecret binary exists at known distribution paths. The script warns if `credential.helper` is currently set to `store` (plaintext) and offers to replace it.

### Commit & Tag Signing (SSH-based)

| Setting | Value | Rationale |
|---------|-------|-----------|
| `gpg.format` | `ssh` | Use SSH keys for signing (simpler than GPG, no agent headaches) |
| `user.signingkey` | (detected/generated) | Path to the user's SSH public key |
| `commit.gpgsign` | `true` | Sign all commits |
| `tag.gpgsign` | `true` | Sign all tags |
| `tag.forceSignAnnotated` | `true` | Belt-and-suspenders with `tag.gpgsign`; ensures annotated tags are signed even if `tag.gpgsign` is later unset |
| `gpg.ssh.allowedSignersFile` | `~/.config/git/allowed_signers` | Path for local signature verification |

### Visibility

| Setting | Value | Rationale |
|---------|-------|-----------|
| `log.showSignature` | `true` | Show signature verification status in git log |

### Optional / Advanced (Interactive Only)

These are offered in interactive mode but **not** applied with `-y` due to workflow impact:

| Setting | Value | Note |
|---------|-------|------|
| `core.symlinks` | `false` | Prevents symlink-based hook injection (CVE-2024-32002). Breaks legitimate symlink workflows. |
| `merge.verifySignatures` | `true` | Refuses to merge unsigned commits. Only viable if entire team signs. |

## Signing Setup Wizard

In interactive mode, the signing wizard runs after the config settings are applied.

### Detection

1. Scan `~/.ssh/` for existing keys by well-known names (`id_ed25519`, `id_ed25519_sk`, `id_ecdsa_sk`) and also check `IdentityFile` directives in `~/.ssh/config` for custom-named keys
2. Check for FIDO2 hardware: `ykman info` or `fido2-token -L`
3. Check git version is 2.34+ (required for SSH signing)

### Tiers

**Tier 1 — Software SSH key (default):**
- If `~/.ssh/id_ed25519` exists, offer to use it
- If not, offer to generate: `ssh-keygen -t ed25519 -C "<user.email>"`
- Configure `user.signingkey` to the public key path

**Tier 2 — FIDO2 hardware key (if hardware detected):**
- Offer to generate: `ssh-keygen -t ed25519-sk -C "<user.email>"`
- Optionally generate as resident key: `ssh-keygen -t ed25519-sk -O resident -O application=ssh:git-signing`
- Print clear prompt: "Touch your security key now..." before the keygen call (it blocks waiting for touch). Do NOT redirect stderr — `ssh-keygen` emits its own touch prompts and progress on stderr.
- Configure `user.signingkey` to the `.pub` file

### With `-y` Mode

- Auto-detect best available key: FIDO2 `ed25519-sk` > software `ed25519`
- If a suitable key exists, verify the public key file is readable before configuring. Then configure and enable signing.
- If no key exists, set only non-breaking signing settings (`gpg.format`, `gpg.ssh.allowedSignersFile`) but do NOT enable `commit.gpgsign` or `tag.gpgsign` (which would break every commit). Print a note to run the script interactively to complete signing setup.

### Allowed Signers File

- Create `~/.config/git/allowed_signers` if it doesn't exist
- Add the user's own public key with their `user.email` as principal
- Print instructions for adding teammates' keys

## SSH Hardening

The script audits and optionally configures `~/.ssh/config` defaults for git-related hosts:

| Setting | Value | Rationale |
|---------|-------|-----------|
| `StrictHostKeyChecking` | `accept-new` | Accept on first connect, reject changes (TOFU). Balances security with usability. |
| `HashKnownHosts` | `yes` | Obscure hostnames in known_hosts — limits info leak if file is compromised |
| `IdentitiesOnly` | `yes` | Only offer explicitly configured keys — prevents key enumeration by malicious servers |
| `AddKeysToAgent` | `yes` | Cache keys in agent after first use |
| `PubkeyAcceptedAlgorithms` | `ssh-ed25519,sk-ssh-ed25519@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com` | Prefer modern algorithms, disallow RSA-SHA1 |

**Application strategy:**
- Create `~/.ssh/` (mode `700`) and `~/.ssh/config` (mode `600`) if they don't exist
- Search for each directive name in the existing config file (simple text match)
- Only add directives that are not already present anywhere in the file
- Append as a `Host *` block at the end of the file
- The script does not modify existing host-specific blocks
- Known limitation: if a directive exists in an `Include`-d file, the script won't detect it. A note is printed advising users with complex SSH configs to review the result.

## Admin Recommendations (Informational Output)

Printed at the end of every run (audit or apply):

- **Branch protection:** Require signed commits on protected branches
- **Vigilant mode:** Enable GitHub/GitLab vigilant mode (flags unsigned commits on profiles)
- **Force push policy:** Set `receive.denyNonFastForwards = true` server-side
- **Token hygiene:** Use fine-grained PATs with short expiry; avoid classic tokens
- **Allowed signers:** Maintain an allowed signers file in repos (or use SSH CA for orgs)
- **Untrusted repos:** Clone with `--no-recurse-submodules` and inspect `.gitmodules` before init

## Non-Goals

- No GPG support — SSH signing covers the same use cases with far less complexity
- No server-side changes — the script only modifies the developer's local config
- No undo/restore — the script is idempotent; devs can manually unset any setting
- No Windows/WSL support
- No modification of existing per-repo configs — global config only

## Dependencies

**Required:**
- `git` >= 2.34.0
- `ssh-keygen`

**Optional (for enhanced features):**
- `ykman` or `fido2-token` — FIDO2 hardware key detection
- OS keychain libraries — `osxkeychain` (macOS), `libsecret` (Linux)

## File Structure

Single file: `git-harden.sh`

Internal organization (functions):

```
main()
parse_args()
detect_platform()
check_dependencies()
audit_git_config()
audit_ssh_config()
audit_signing()
print_audit_report()
apply_git_config()
apply_ssh_config()
signing_wizard()
detect_existing_keys()
detect_fido2_hardware()
generate_ssh_key()
generate_fido2_key()
setup_allowed_signers()
print_admin_recommendations()
prompt_yn()           # helper: prompt with default
print_ok()            # helper: green [OK]
print_warn()          # helper: yellow [WARN]
print_miss()          # helper: red [MISS]
```
