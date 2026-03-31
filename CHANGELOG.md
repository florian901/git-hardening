# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.2.3] - 2026-03-31

### Fixed
- FIDO2 key generation on macOS — detect Homebrew's openssh via `ssh-sk-helper` (no freeze), use its `ssh-keygen` binary for hardware key generation
- Linux gitleaks install hint now shows `apt`/`dnf` instead of `brew`
- e2e test runner distro loop broken by `IFS` setting — use bash array

### Changed
- Group interactive apply prompts into 6 categories with one-line explanations (replaces ~25 individual prompts)

## [0.2.0] - 2026-03-31

### Added
- Gitleaks pre-commit hook installation — creates `~/.config/git/hooks/pre-commit` with `SKIP_GITLEAKS` bypass
- Global gitignore creation (`~/.config/git/ignore`) with security patterns (`.env`, `*.pem`, `*.key`, credentials, Terraform state)
- Audit of existing global gitignore for missing security patterns
- 8 new git config settings: `user.useConfigOnly`, `protocol.version=2`, `transfer.bundleURI=false`, `init.defaultBranch=main`, `core.symlinks=false` (interactive-only), `fetch.prune=true`, `gc.reflogExpire=180.days`, `gc.reflogExpireUnreachable=90.days`
- Combined signing enablement into single prompt (replaces 3 individual prompts)
- 26 new BATS tests (90 total)

### Security
- SSH key hygiene audit — scans `~/.ssh/*.pub` and `IdentityFile` entries, warns about DSA/ECDSA/weak RSA keys
- Plaintext credential file detection — warns about `~/.git-credentials`, `~/.netrc`, `~/.npmrc` (auth tokens), `~/.pypirc` (passwords)
- `safe.directory = *` wildcard detection and removal (CVE-2022-24765)

### Fixed
- `ssh-keygen` calls fail on macOS with `--` end-of-options separator (removed)
- Interactive tests fail on macOS due to tmux resetting `HOME` in login shells
- Interactive tests race condition with tmux session cleanup between tests

## [0.1.0] - 2026-03-30

### Added
- Interactive shell script that audits and hardens global git config
- Audit mode (`--audit`) with color-coded report and CI-friendly exit codes
- Auto-apply mode (`-y`) for unattended hardening
- Object integrity checks (`transfer.fsckObjects`, `fetch.fsckObjects`, `receive.fsckObjects`)
- Protocol restrictions with default-deny policy (blocks `git://` and `ext://`)
- Filesystem protection (`core.protectNTFS`, `core.protectHFS`, `core.fsmonitor=false`)
- Hook execution control via `core.hooksPath` redirection
- Repository safety (`safe.bareRepository=explicit`, `submodule.recurse=false`)
- Pull/merge hardening (`pull.ff=only`, `merge.ff=only`) with `pull.rebase` conflict detection
- Transport security (HTTP-to-HTTPS rewrite, `http.sslVerify=true`)
- Platform-detected credential helper (`osxkeychain` on macOS, `libsecret` on Linux)
- SSH signing setup wizard with two tiers: software ed25519 and FIDO2 hardware keys
- SSH config hardening (`StrictHostKeyChecking`, `HashKnownHosts`, `IdentitiesOnly`, algorithm restrictions)
- Allowed signers file management
- Pre-execution safety review gate with AI assistant review instructions
- OSINT privacy advisory about signing key reuse across orgs
- Admin/org-level recommendations printed at end of every run
- Config backup before applying changes
- BATS test suite with 64 tests

### Security
- Safe tilde expansion without `eval`
- SSH config value parsing handles inline comments and quoted paths
- Version comparison uses base-10 arithmetic to prevent octal interpretation
- Temp file cleanup trap in SSH config updates
