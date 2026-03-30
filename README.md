# git-harden.sh

Audit and harden your global git configuration with security-focused defaults.

Protects against history rewriting, supply chain attacks, credential theft, and malicious repository exploitation. Runs on macOS and Linux.

## Quick Start

```bash
# Download and run
curl -O https://raw.githubusercontent.com/<you>/git-hardening/main/git-harden.sh
chmod +x git-harden.sh

# Audit your current config (no changes)
./git-harden.sh --audit

# Interactive mode — review and approve each change
./git-harden.sh

# Apply all recommended defaults without prompting
./git-harden.sh -y
```

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
| **Object integrity** | Validates all objects on fetch/push/receive (`transfer.fsckObjects`, etc.) |
| **Protocol restrictions** | Default-deny policy: only HTTPS and SSH allowed. Blocks `git://` (unencrypted) and `ext://` (arbitrary command execution) |
| **Filesystem protection** | Enables `core.protectNTFS`, `core.protectHFS`, disables `core.fsmonitor` |
| **Hook control** | Redirects `core.hooksPath` to `~/.config/git/hooks` so repo-local hooks can't execute |
| **Repository safety** | `safe.bareRepository=explicit`, `submodule.recurse=false` |
| **Pull/merge hardening** | `pull.ff=only`, `merge.ff=only` — refuses non-fast-forward merges, surfacing rewritten history |
| **Transport security** | Rewrites `http://` to `https://`, enforces `http.sslVerify=true` |
| **Credential storage** | Platform-detected secure helper (`osxkeychain` on macOS, `libsecret` on Linux). Warns if using plaintext `store` |
| **Commit signing** | SSH-based signing with interactive key setup wizard (software or FIDO2 hardware key) |
| **SSH hardening** | `StrictHostKeyChecking=accept-new`, `HashKnownHosts=yes`, `IdentitiesOnly=yes`, modern algorithm restrictions |
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
- `ykman` or `fido2-token` for FIDO2 hardware key detection

## Threat Model

### What this protects against

- **History rewriting** — `pull.ff=only` and `merge.ff=only` refuse non-fast-forward operations, making force-pushed changes visible
- **Object injection** — `fsckObjects` validates every object transferred, catching corruption or malicious payloads
- **Protocol downgrade** — blocks plaintext `git://` and dangerous `ext://` protocol
- **Hook-based RCE** — redirects hook execution away from repo-local `.git/hooks/`
- **Submodule attacks** — disables auto-recursion; submodules must be explicitly initialized
- **Credential theft** — ensures secure credential storage, warns about plaintext `store`
- **Commit impersonation** — SSH signing proves key possession (anyone can fake `user.name`/`user.email`)
- **Filesystem tricks** — blocks NTFS/HFS+ path manipulation attacks

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

## License

MIT
