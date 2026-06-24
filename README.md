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

### Agent-Backed Keys (1Password / Bitwarden) — Quick Start

The goal: working signing **and** authentication with **zero plaintext private keys on disk**. The private key stays inside your vault's SSH agent; the script audits and configures around it. (Background and threat model: [`docs/REASONING.md` → "Agent-Backed Keys"](docs/REASONING.md).)

1. **Enable the SSH agent in your vault app.**
   - **1Password:** Settings → Developer → "Use the SSH agent". 1Password exposes a socket and asks for biometric/Touch ID approval per use.
   - **Bitwarden:** Settings → enable "SSH agent". Bitwarden exposes `~/.bitwarden-ssh-agent.sock`.

2. **Point ssh at the vault socket.** Add to `~/.ssh/config` (or let your vault app manage it):
   ```
   # 1Password (macOS)
   Host *
     IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
   ```
   On Linux/Bitwarden, set `SSH_AUTH_SOCK` (or `IdentityAgent`) to the agent socket your app prints.

3. **Confirm the agent holds your key** (read-only; never exposes private material):
   ```bash
   ssh-add -L          # lists public keys the agent can sign with
   ```

4. **Run the audit.** The script probes reachable agents read-only, lists their keys, and configures signing without needing any `~/.ssh/id_*` private file:
   ```bash
   ./git-harden.sh --audit      # then drop --audit to apply
   ```
   - Signing is configured with `user.signingkey = key::ssh-ed25519 …` (the literal public key — no file on disk).
   - Before applying `IdentitiesOnly yes`, the script offers to write **public-key stubs** (`~/.ssh/<name>.pub`, public material only) so agent keys keep being offered. Decline and it skips the directive rather than locking you out.

5. **(Optional) migrate an existing on-disk key into the vault** with `--migrate`: it prints the import steps, and *after* the agent shows the imported key, offers to remove the plaintext private file (interactive only, default **No**, never in `-y`; the `.pub` stub is kept).

**Inside a forwarded SSH session** (`SSH_AUTH_SOCK` set with `SSH_CONNECTION`/`SSH_TTY`), the script labels the agent "forwarded" and makes no file-based assumptions. Forward your agent only to hosts you trust — anyone who can read the forwarded socket can borrow (not extract) your key for the life of the connection.

## Moving secrets into 1Password

`git-harden.sh` includes a **Secret Inventory** that scans for plaintext developer credentials beyond SSH keys — `~/.aws/credentials`, cloud-CLI tokens, package-registry tokens, kubeconfigs, database passwords, and `.env` files. For each it reports the **kind and path** (never the value), offers to `chmod 600` any group/world-readable file, and prints the exact 1Password next step. It never reads a secret value into output, never creates vault items, and never deletes a credential file. (Rationale: [`docs/REASONING.md` → "Plaintext Secret Inventory"](docs/REASONING.md).)

```bash
# Read-only: list plaintext credentials and their migration steps
./git-harden.sh --audit

# Deeper project trees? Raise the .env walk depth (default 2)
./git-harden.sh --audit --scan-depth 3
```

The advisor tailors each step to whether the 1Password CLI (`op`) is installed:

- **Shell-plugin CLIs** (`aws`, `gh`, `glab`, `terraform`, `vault`, `stripe`, `openai`, `vercel`, `circleci`) — initialize the 1Password shell plugin, then delete the plaintext:
  ```bash
  op plugin init aws          # authenticates the CLI through 1Password
  rm ~/.aws/credentials       # printed as a follow-up — you run it
  ```
- **Config-file CLIs** (kubeconfig, docker, npm, pypi, netrc, pgpass, maven, cargo, composer, rubygems, gcloud) — use a 1Password secret-reference template so the config reads from the vault at runtime:
  ```bash
  # Replace the literal token with an op:// reference, then run the tool via op
  op inject -i ~/.npmrc.tpl -o ~/.npmrc      # ‡ idiomatic — confirm with op --help
  ```
- **`.env` / dotfile tokens** — keep secrets out of the file with `op run`:
  ```bash
  op run --env-file=.env -- your-command     # values resolved from op:// references
  ```
- **SSH / GPG keys** — use the agent path above, not a file.

If `op` is not installed, the advisor prints the install pointer (<https://developer.1password.com/docs/cli/get-started/>) and still prints each per-finding step. The inventory's `.env`/dotfile findings are hygiene-tier and do **not** fail `--audit`; long-lived cloud and registry credentials are security-tier and do.

## Usage

```
git-harden.sh [OPTIONS]

Options:
  --audit          Audit only, no changes (exit code 2 if security issues found)
  -y, --yes        Auto-apply all recommended defaults (never deletes anything)
  --reset-signing  Remove signing config (interactive deletion of *_signing keys)
  --migrate        Guided migration of on-disk private keys to a vault SSH agent
  --scan-depth N   Depth below $HOME for the .env secret-inventory walk (default 2)
  --help, -h       Show help
  --version        Show version
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
- **Credential theft** — ensures secure credential storage, warns about plaintext `store`, and runs a Secret Inventory that detects plaintext developer credentials beyond SSH keys (`~/.aws/credentials`, cloud-CLI and registry tokens, kubeconfigs, database passwords, `.env` files), tightens their permissions, and prints 1Password migration steps
- **Plaintext private keys** — flags unencrypted `~/.ssh` private keys and steers toward vault-backed SSH agents (1Password/Bitwarden) so no plaintext key need live on disk
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

## Signing with FIDO2 hardware keys

The script includes an interactive wizard that:

1. Detects existing SSH keys (including custom-named keys from `~/.ssh/config`)
2. Detects FIDO2 hardware (YubiKey, etc.)
3. Offers two tiers:
   - **Software SSH key** — use existing `ed25519` or generate one
   - **FIDO2 hardware key** — generate `ed25519-sk` with touch-to-sign (if hardware detected)
4. Configures `user.signingkey`, `commit.gpgsign`, `tag.gpgsign`
5. Sets up `~/.config/git/allowed_signers` for local signature verification

These combinations of hardware and OS have been tested:

| Hardware | Firmware | OS | works? |
|----------|----------|----|--------|
| [Yubico Security Key USB C NFC](https://support.yubico.com/s/article/Security-Key-C-NFC) | 5.4.3 | macOS Tahoe | Yes |
| [Yubico Security Key USB C NFC](https://support.yubico.com/s/article/Security-Key-C-NFC) | 5.4.3 | Debian 13 Trixie |  |
| [Yubico Security Key USB C NFC](https://support.yubico.com/s/article/Security-Key-C-NFC) | 5.4.3 | Fedora 42 | Yes |
| [Yubico Security Key USB A NFC](https://support.yubico.com/s/article/Security-Key-NFC) | 5.4.3 | macOS Tahoe | Yes |
| [Yubico Security Key USB A NFC](https://support.yubico.com/s/article/Security-Key-NFC) | 5.4.3 | Debian 13 Trixie |  |
| [Yubico Security Key USB A NFC](https://support.yubico.com/s/article/Security-Key-NFC) | 5.4.3 | Fedora 42 | Yes |
| [Yubico Security Key USB A NFC](https://www.yubico.com/products/security-key-by-yubico/usb-a-nfc/) | 5.0.2 | macOS Tahoe | Yes |
| [Yubico Security Key USB A NFC](https://www.yubico.com/products/security-key-by-yubico/usb-a-nfc/) | 5.0.2 | Debian 13 Trixie |  |
| [Yubico Security Key USB A NFC](https://www.yubico.com/products/security-key-by-yubico/usb-a-nfc/) | 5.0.2 | Fedora 42 | Yes |
| [Yubico YubiKey 5C nano](https://support.yubico.com/s/article/YubiKey-5C-Nano) | 5.4.3 | macOS Tahoe | Yes |
| [Yubico YubiKey 5C nano](https://support.yubico.com/s/article/YubiKey-5C-Nano) | 5.4.3 | Debian 13 Trixie | Yes |
| [Yubico YubiKey 5C nano](https://support.yubico.com/s/article/YubiKey-5C-Nano) | 5.4.3 | Fedora 42 | Yes |
| [Yubico YubiKey 5 NFC](https://support.yubico.com/s/article/YubiKey-5-NFC) | 5.1.2 | macOS Tahoe | Yes |
| [Yubico YubiKey 5 NFC](https://support.yubico.com/s/article/YubiKey-5-NFC) | 5.1.2 | Debian 13 Trixie| Yes  |
| [Yubico YubiKey 5 NFC](https://support.yubico.com/s/article/YubiKey-5-NFC) | 5.1.2 | Fedora 42| Yes |
| [SoloKeys Solo 1 Tap USB-A](https://solokeys.com/collections/all/products/solo-tap-usb-a-preorder) |  | Ubuntu 24.04 | Yes |
| [SoloKeys Solo 1 Tap USB-A](https://solokeys.com/collections/all/products/solo-tap-usb-a-preorder) |  | Debian 13 Trixie | Yes |
| [SoloKeys Solo 1 Tap USB-A](https://solokeys.com/collections/all/products/solo-tap-usb-a-preorder) |  | Fedora 42 | Yes |
| [SoloKeys Solo 1 Tap USB-A](https://solokeys.com/collections/all/products/solo-tap-usb-a-preorder) |  | macOS Tahoe | Yes |
| [HYPERSECU HyperFIDO mini](https://033c2a7e-e1da-473d-a255-6132a1d3aa6e.filesusr.com/ugd/5aae8d_f4e8a196a99f45b1859e201a7cb40962.pdf) |  | macOS Tahoe | Yes |
| [HYPERSECU HyperFIDO mini](https://033c2a7e-e1da-473d-a255-6132a1d3aa6e.filesusr.com/ugd/5aae8d_f4e8a196a99f45b1859e201a7cb40962.pdf) |  | Ubuntu 24.04 | Yes |
| [HYPERSECU HyperFIDO mini](https://033c2a7e-e1da-473d-a255-6132a1d3aa6e.filesusr.com/ugd/5aae8d_f4e8a196a99f45b1859e201a7cb40962.pdf) |  | Debian 13 Trixie | |
| [HYPERSECU HyperFIDO mini](https://033c2a7e-e1da-473d-a255-6132a1d3aa6e.filesusr.com/ugd/5aae8d_f4e8a196a99f45b1859e201a7cb40962.pdf) |  | Fedora 42 | Yes |


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
