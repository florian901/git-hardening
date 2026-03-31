# git-harden.sh

Audit and harden your global git configuration with security-focused defaults.

Protects against history rewriting, supply chain attacks, credential theft, and malicious repository exploitation. Runs on macOS and Linux.

## Quick Start

```bash
# Clone and run
git clone https://github.com/YOUR_ORG/git-hardening.git
cd git-hardening
chmod +x git-harden.sh

# Audit your current config (no changes)
./git-harden.sh --audit

# Interactive mode — review and approve each change
./git-harden.sh

# Apply all recommended defaults without prompting
./git-harden.sh -y
```

On first interactive run, the script asks you to confirm you've reviewed it for safety. If you haven't, it prints instructions for piping it to Claude Code or Gemini CLI for an automated review.

## What It Does

The script runs in two phases:

1. **Audit** — scans your current `git config --global` and `~/.ssh/config`, prints a color-coded report:
   - `[OK]` already set to the recommended value
   - `[WARN]` set to a non-recommended value
   - `[MISS]` not configured
2. **Apply** — for each non-OK setting, shows what it does and prompts you to accept or skip (or auto-applies with `-y`)

### Settings Applied

| Category | What it does |
|---|---|
| **Identity** | `user.useConfigOnly=true` — prevents commits without explicit identity |
| **Object integrity** | `fsckObjects` on transfer/fetch/receive, `transfer.bundleURI=false`, `fetch.prune=true` |
| **Protocol restrictions** | Default-deny policy: only HTTPS and SSH. Blocks `git://` and `ext://`. Forces `protocol.version=2` |
| **Filesystem protection** | `core.protectNTFS`, `core.protectHFS`, `core.fsmonitor=false`, `core.symlinks=false` (interactive-only) |
| **Hook control** | Redirects `core.hooksPath` to `~/.config/git/hooks` so repo-local hooks can't execute |
| **Pre-commit hook** | Installs gitleaks secret scanner as global pre-commit hook (with `SKIP_GITLEAKS` bypass) |
| **Repository safety** | `safe.bareRepository=explicit`, `submodule.recurse=false`, detects/removes `safe.directory=*` wildcard |
| **Pull/merge hardening** | `pull.ff=only`, `merge.ff=only` — refuses non-fast-forward merges |
| **Transport security** | Rewrites `http://` to `https://`, enforces `http.sslVerify=true` |
| **Credential storage** | Platform-detected secure helper (`osxkeychain` on macOS, `libsecret` on Linux). Warns if using plaintext `store` |
| **Credential hygiene** | Warns about plaintext `~/.git-credentials`, `~/.netrc`, `~/.npmrc` (tokens), `~/.pypirc` (passwords) |
| **Global gitignore** | Creates `~/.config/git/ignore` with patterns for secrets, credentials, and OS/IDE artifacts |
| **Defaults** | `init.defaultBranch=main` |
| **Forensic readiness** | Extended reflog retention (`gc.reflogExpire=180.days`, `gc.reflogExpireUnreachable=90.days`) |
| **Commit signing** | SSH-based signing with interactive key setup wizard (software or FIDO2 hardware key) |
| **SSH hardening** | `StrictHostKeyChecking=accept-new`, `HashKnownHosts=yes`, `IdentitiesOnly=yes`, modern algorithm restrictions |
| **SSH key hygiene** | Audits `~/.ssh/*.pub` for weak key types (DSA, ECDSA, short RSA) |
| **Visibility** | `log.showSignature=true` |

A config backup is saved to `~/.config/git/pre-harden-backup-<timestamp>.txt` before any changes.

### Signing Setup

The script includes an interactive wizard that:

1. Detects existing SSH keys (including custom-named keys from `~/.ssh/config`)
2. Detects FIDO2 hardware (YubiKey, etc.)
3. Offers two tiers:
   - **Software SSH key** — use existing `ed25519` or generate one
   - **FIDO2 hardware key** — generate `ed25519-sk` with touch-to-sign (if hardware detected)
4. Configures `user.signingkey`, `commit.gpgsign`, `tag.gpgsign`
5. Sets up `~/.config/git/allowed_signers` for local signature verification

With `-y`, the script auto-detects the best available key. If no key exists, signing config is prepared but not enabled (to avoid breaking commits).

**Privacy note:** The signing wizard warns that reusing the same signing key across personal and work accounts enables cross-platform identity correlation (OSINT risk). For identity separation, generate dedicated keys per context and use git's `includeIf` for per-org config.

## Usage

```
git-harden.sh [OPTIONS]

Options:
  --audit       Audit only, no changes (exit code 2 if issues found)
  -y, --yes     Auto-apply all recommended defaults
  --help, -h    Show help
  --version     Show version
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All OK, or changes applied successfully |
| 1 | Error (missing dependencies, etc.) |
| 2 | Audit found issues (`--audit` mode) |

## Requirements

- `git` >= 2.34.0 (required for SSH signing)
- `ssh-keygen`
- Bash 3.2+ (compatible with macOS default bash)

Optional:
- `gitleaks` for pre-commit secret scanning (hook is installed regardless; scans run only if gitleaks is on `$PATH`)
- `ykman` or `fido2-token` for FIDO2 hardware key detection

## Threat Model

### What this protects against

- **History rewriting** — `pull.ff=only` and `merge.ff=only` refuse non-fast-forward operations, making force-pushed changes visible
- **Object injection** — `fsckObjects` validates every object transferred, catching corruption or malicious payloads
- **Protocol downgrade** — blocks plaintext `git://` and dangerous `ext://` protocol
- **Hook-based RCE** — redirects hook execution away from repo-local `.git/hooks/`
- **Submodule attacks** — disables auto-recursion; submodules must be explicitly initialized
- **Credential theft** — ensures secure credential storage, warns about plaintext `store`, detects leaked credentials in `~/.git-credentials`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`
- **Secret leakage** — gitleaks pre-commit hook blocks commits containing secrets before they enter git history
- **Commit impersonation** — SSH signing proves key possession (anyone can fake `user.name`/`user.email`)
- **Filesystem tricks** — blocks NTFS/HFS+/symlink path manipulation attacks
- **Weak SSH keys** — audits and warns about DSA, ECDSA, and short RSA keys

### What this does NOT protect against

- A compromised machine (malware can use cached keys)
- Malicious code from an authorized signer
- Historical unsigned commits (signing is not retroactive)
- Server-side misconfigurations (see admin recommendations printed by the script)

## Admin Recommendations

The script prints (but does not apply) server/org-level recommendations:

- Enable "require signed commits" on protected branches
- Enable GitHub/GitLab vigilant mode
- Restrict force-pushes server-side
- Use fine-grained, short-lived tokens in CI/CD
- Maintain an allowed signers file in repos
- Clone untrusted repos with `--no-recurse-submodules`
- Use separate signing keys per org to prevent cross-platform identity correlation (OSINT)

## Running Tests

```bash
# Init test framework submodules (first time only)
git submodule update --init --recursive

# Unit tests (BATS) — runs in isolated $HOME, never touches real config
./test/run.sh

# Interactive tests (tmux) — tests the full interactive flow on macOS/Linux
./test/run-interactive.sh

# Full e2e matrix — containers + interactive tests across distros
# Requires docker or podman
./test/e2e.sh                                    # All distros + host
./test/e2e.sh --skip-host ubuntu                 # Single distro, skip host
./test/e2e.sh --runtime podman --skip-host       # All distros via podman
./test/e2e.sh --rebuild alpine                   # Force image rebuild
```

| Test tier | What it covers | Requirements |
|-----------|---------------|--------------|
| `test/run.sh` | 92 BATS unit tests — config audit, apply, signing, key detection | `bats-core` submodule |
| `test/run-interactive.sh` | 4 tmux-driven tests — full accept, safety gate, signing wizard | `tmux` |
| `test/e2e.sh` | Container matrix (Ubuntu, Debian, Fedora, Alpine, Arch) + host interactive | `docker` or `podman` |

All tests run in isolated environments and never modify your real git or SSH configuration.

## License

MIT
