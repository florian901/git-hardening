# git-harden.sh — Agent-Backed Keys: 1Password / Bitwarden / Forwarded Agents, Zero Plaintext Keys on Disk

Status: **proposed** (plan for v0.7.0)
Depends on: v0.6.0 (scope-aware SSH config handling, key inventory via `ssh-add -L`, signing smoke test)

## Motivation

The script currently assumes file-based keys: it scans `~/.ssh/*.pub`, generates keys to disk, and treats "no key files" as "no keys". That assumption breaks — and in some places actively fights — the strongest available key-storage model:

- **1Password / Bitwarden SSH agents** hold private keys encrypted in a vault and expose them only through an agent socket, with per-use approval prompts. No private key ever touches disk.
- **Hardware keys** (FIDO2 resident keys) keep the private key in the authenticator.
- **Forwarded agents** (`SSH_AUTH_SOCK` in a remote/container session) let agent-less environments — including agent containers used for AI-assisted development — sign and authenticate without holding any identity locally.

The end state this plan targets: **a machine can pass the full audit and have working signing + authentication with zero plaintext private keys on disk.** Today it can't: the audit reports "No SSH public keys found", the signing wizard only offers to generate file-based keys, and `IdentitiesOnly yes` (which we set) can silently break agent-only setups.

## Current gaps

| # | Gap | Where |
|---|-----|-------|
| 1 | Key hygiene audit ignores agent-held keys ("No SSH public keys found" on a fully provisioned 1Password machine) | `audit_ssh_key_hygiene` |
| 2 | Signing wizard offers only on-disk generation (software file or FIDO2 file handle) | `signing_wizard` |
| 3 | `IdentitiesOnly yes` is applied without checking that configured `IdentityFile` stubs exist — agent-only keys stop being offered | `apply_ssh_config` |
| 4 | No detection of *unencrypted* private keys on disk — the exact artifact this plan wants to eliminate | missing audit |
| 5 | No `ForwardAgent` policy; forwarded-agent risk/benefit is undocumented | missing audit + docs |
| 6 | Signing smoke test requires a private key file next to the `.pub` | `verify_signing_setup` |

## Design

### Phase 1 — Detection & audit (no behavior changes)

**1a. Agent detection helper.** `detect_ssh_agents` reports every reachable agent:

- `SSH_AUTH_SOCK` (generic; also covers forwarded agents — detect forwarding via `SSH_CONNECTION`/`SSH_TTY` being set alongside it)
- 1Password: `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock` (macOS), `~/.1password/agent.sock` (Linux)
- Bitwarden: `~/.bitwarden-ssh-agent.sock`
- gpg-agent: `gpgconf --list-dirs agent-ssh-socket`

Probe each socket with `SSH_AUTH_SOCK=<sock> ssh-add -L`; report agent type, reachability, and key count. Sockets are *probed read-only*; nothing is written.

**1b. Agent keys join the key-hygiene audit.** `audit_ssh_key_hygiene` merges `ssh-add -L` output (per detected agent) with on-disk `.pub` files, deduplicated by key blob. Agent keys get the same weak-algorithm checks and are labeled `(agent: 1password)` etc. "No SSH public keys found" only appears when disk *and* agents are empty.

**1c. New audit: plaintext private keys on disk** (tier: security).

- Enumerate candidate private keys in `~/.ssh` (files whose first line is an OpenSSH/PEM private key header — never by filename guessing).
- Classify encrypted vs. unencrypted: `ssh-keygen -y -P "" -f <key>` succeeding in batch mode ⇒ **unencrypted**.
- `[WARN security]` unencrypted private key on disk → recommend vault import + passphrase or deletion after migration.
- `[INFO]` encrypted private key on disk when an agent holds the same public key → candidate for cleanup (Phase 4).
- Audit-only, like the existing credential-hygiene section: never modify or delete.

**1d. `ForwardAgent` audit** (tier: security). `[OK]` when unset/`no` globally; `[WARN]` when `yes` in global scope ("any root user on any host you ssh to can use your keys while connected — scope it per-host, prefer agents with per-use confirmation"). Uses the v0.6.0 scope-aware reader.

### Phase 2 — Signing without key files

**2a. Wizard option 3: "Use a key from your SSH agent".** Lists agent keys (`ssh-add -L`, modern algorithms only), lets the user pick one, then:

- `user.signingkey = key::<keytype> <blob> <comment>` (literal pub key, no file needed; supported since Git 2.34 for `gpg.format=ssh`)
- allowed_signers entry written from the same literal key (existing `setup_allowed_signers` path, fed by string instead of file — refactor it to accept key material, keeping the public-key validation guard)
- In `-y` mode with no file-based key found: if exactly one modern agent key exists, use it (consistent with the existing "found existing key" auto-pick); otherwise skip with the current message.

**2b. Smoke test via agent.** `verify_signing_setup` learns a second path: when no private key file exists, sign with `ssh-keygen -Y sign -U -f <tmp pubkey file>` (`-U`: private half lives in the agent). Same prompt gating — 1Password/Bitwarden will pop an approval dialog, which is exactly what we want the user to see once at setup time.

**2c. Audit accepts `key::` signing keys.** `audit_signing` currently prints `(inline key)` for `ssh-*` values; extend the case to `key::*` and verify the *allowed_signers* file contains the same blob.

### Phase 3 — SSH config integration

**3a. `IdentitiesOnly` guard.** Before applying `IdentitiesOnly yes`, check: does any `IdentityFile` directive exist in global scope, or do on-disk `.pub` stubs match agent keys? If the user is agent-only with no stubs, offer to write **public-key stubs** (`~/.ssh/<name>.pub` — public material only, consistent with the zero-plaintext goal) plus matching `IdentityFile` lines, so `IdentitiesOnly yes` keeps working with the agent. Decline ⇒ skip the directive with a warning instead of applying a lockout.

**3b. `IdentityAgent` offering.** When a 1Password/Bitwarden socket is detected and `SSH_AUTH_SOCK` doesn't already point at it, offer a global `IdentityAgent <socket>` directive (written with the v0.6.0 append-at-EOF semantics). Never overwrite an existing `IdentityAgent`.

**3c. `ForwardAgent no` as an applied default** (matching the Phase 1d audit), with documentation of the per-host override pattern and a note that confirmation-prompting agents (1Password, `ssh-add -c`) are the safe way to use forwarding when it's unavoidable.

### Phase 4 — Migration assistant (interactive only, opt-in)

Goal: walk an existing file-based user to zero plaintext keys. Strictly guided, never automatic:

1. Inventory on-disk private keys (from 1c) and show which are already represented in an agent.
2. Print vault-import instructions per detected agent (1Password and Bitwarden import flows differ; we print, we don't drive their CLIs).
3. After the user confirms a key is imported **and** the agent probe shows its public key, offer deletion of the on-disk private key under the v0.6.0 reset-signing safety rules: interactive only, default **No**, rename-to-`.bak` middle option, never in `-y` mode, keep the `.pub` stub for `IdentitiesOnly`.
4. Re-run the relevant audits to show the end state.

### Documentation

- New REASONING.md section "Agent-Backed Keys" covering: why vault agents beat files, forwarded-agent threat model, `key::` signing, pub-stub pattern for `IdentitiesOnly`.
- README quick-start for 1Password/Bitwarden users.

## Acceptance criteria

1. On a machine whose only keys live in a 1Password agent: full audit passes (given config applied), `audit_ssh_key_hygiene` lists the agent keys, signing works via `key::`, and the smoke test round-trips through the agent.
2. `git-harden.sh -y` never blocks on an agent approval prompt and never deletes/moves any key file.
3. Applying `IdentitiesOnly yes` is impossible in a state that would stop agent keys from being offered (stub-write or skip-with-warning).
4. An unencrypted private key in `~/.ssh` is flagged as a security-tier finding; an encrypted one is not flagged red.
5. Forwarded-agent sessions (`SSH_AUTH_SOCK` + `SSH_CONNECTION`) are detected and labeled; no file-based assumptions break inside such a session or an agent container.
6. All existing BATS tests keep passing; new tests use a throwaway `ssh-agent` (start, `ssh-add` a generated key, delete the private file, point `SSH_AUTH_SOCK` at it) so CI needs no vault products.

## Test plan

- **Unit (BATS):** agent detection with fake sockets; key inventory merge/dedup; unencrypted-key classifier (generated with/without `-N`); `key::` signingkey audit; `IdentitiesOnly` guard paths (stubs present / agent-only / decline).
- **Agent integration (BATS, real `ssh-agent`):** sign + verify via `-U` with the private key file removed — proves the zero-plaintext path end to end.
- **Container e2e:** extend `test/containers/*` with an `ssh-agent`-only variant (no `~/.ssh/id_*` private files) running `--audit` and `-y`.
- **Interactive:** new `test/interactive/test-signing-agent.sh` covering wizard option 3.

## Non-goals

- Driving 1Password/Bitwarden CLIs (`op`, `bws`) — instructions only; their CLIs change and require auth sessions.
- gpg-agent-backed *GPG* signing (this project standardizes on SSH signing).
- Hardware-token provisioning changes (FIDO2 path already exists and is orthogonal).

## Open questions

1. Should `-y` auto-adopt a single agent key for signing (2a) or stay fully passive? Current plan: adopt only when exactly one modern key exists, mirroring file-based behavior. Approval prompts make even this debatable in headless runs — the smoke test stays interactive-only either way.
2. Bitwarden's agent socket path is configurable; do we read its `data.json` to find it, or only check the default path and document the rest? Plan: default path + docs.
3. Stub naming for written `.pub` stubs (3a): derive from the key comment (sanitized) or `agent_<fingerprint-prefix>.pub`? Plan: comment-derived with fingerprint fallback.
