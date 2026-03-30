# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-03-31

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
- `--` separator before path arguments in `ssh-keygen` calls
- Removed unused exported `SIGNING_KEY_PATH` variable
