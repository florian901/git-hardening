# spec: Plaintext Secret Inventory + 1Password Migration Advisor

Status: **proposed** (v0.8)
Depends on: v0.6.0 (audit tiers, scope-aware helpers, portable temp/permission handling)
Informed by: [`docs/research/2026-06-23-plaintext-secret-surfacing.md`](../research/2026-06-23-plaintext-secret-surfacing.md)
Tracking: issue #55

## Overview

When a developer runs `git-harden.sh`, a new **Secret Inventory** section scans their machine for plaintext (or trivially recoverable) developer/CLI credentials beyond SSH keys — AWS keys, cloud-CLI tokens, package-registry tokens, container/k8s configs, database client passwords, and `.env` files. For every credential it finds, it:

1. Reports the **kind and path** (never the value) at a severity tier.
2. Flags any that are **group- or world-readable** and offers to `chmod 600` them.
3. Prints the **exact 1Password next step** to migrate that credential into a vault, tailored to whether the `op` CLI is installed.

The section is audit-only except for the permission fix: it never reads secret values into output, never creates vault items, and never deletes a credential file. `--audit` reports findings read-only; the apply phase adds the optional `chmod` fix and the advisor.

`.env` discovery walks `$HOME` to a bounded depth (default 2 directory levels, covering `$HOME/projects/<repo>/.env`), overridable with `--scan-depth N`.

## Purpose

Reduce the blast radius of a local compromise (infostealer malware, a leaked backup, a shared machine). Long-lived plaintext cloud and registry credentials on disk are the highest-value, lowest-effort target for an attacker who gets any code execution as the user. The script already audits four such files; this generalizes that into a comprehensive inventory and attaches concrete, vault-specific remediation so the finding is actionable rather than just alarming.

### Non-Goals

- **Bitwarden support.** This spec is 1Password-only. The research doc covers Bitwarden; a later spec can add a `bw`/`bws` advisor track. Advisor wording here is 1Password-specific.
- **Driving the `op` CLI.** The advisor prints commands; it never runs `op item create`, `op plugin init`, etc. on the user's behalf, and never requires an authenticated 1Password session.
- **Deleting or moving credential files.** The "delete the plaintext after migrating" step is printed for the user to perform. The only mutation this feature performs is `chmod`.
- **Reading, printing, or logging secret values.** Output is path + kind only.
- **OS keychain / Secret Service / browser password store enumeration.** Out of scope by maintainer decision.
- **Secret rotation**, expiry checking, or validity testing of found credentials.
- **Recursive unbounded `$HOME` scanning.** Depth is bounded and configurable; deeper trees require an explicit larger `--scan-depth`.
- **Scanning arbitrary directories outside `$HOME`** (and the current working directory at depth 0).

## User Stories

**As a** developer with `~/.aws/credentials` holding static access keys
**I want** the script to tell me they exist and give me the exact `op plugin init aws` command
**So that** I can move them into 1Password and delete the plaintext file without researching how.

**As a** developer whose `~/.pgpass` is mode 644
**I want** the script to offer to `chmod 600` it
**So that** other local accounts can't read my database password.

**As a** security lead running `git-harden.sh --audit` in a fleet check
**I want** plaintext long-lived credentials to fail the audit (exit 2) while noisy `.env`/dotfile findings only warn
**So that** the gate flags real exposure without drowning in false positives.

**As a** developer who keeps repos in `~/projects/<repo>`
**I want** `.env` files there surfaced by default, and a `--scan-depth` flag when my layout is deeper
**So that** project secrets are covered without a slow full-home scan.

## Functional Requirements

### FR1 — Secret detection registry

The inventory is driven by a fixed registry. Each entry is `(kind, location, method, tier, op_mechanism)`. Two implementations consuming this table must produce identical findings.

**Detection methods:**
- `exists` — file is present (the file's existence alone implies a credential).
- `content:<ERE>` — file is present **and** `grep -qE '<ERE>'` matches (the file is config that *may* embed a secret).
- Every detected file (by either method) is additionally subject to the FR3 permission check.

**Registry (clear-cut, `exists` or strong `content`, tier = security):**

| Kind | Location | Method |
|---|---|---|
| git credentials | `~/.git-credentials` | exists |
| AWS static keys | `~/.aws/credentials` | content:`aws_secret_access_key` |
| GCP app-default creds | `~/.config/gcloud/application_default_credentials.json` | exists |
| GCP service-account key | `~/.config/gcloud/legacy_credentials/**`, and any `content:"type":[[:space:]]*"service_account"` + `"private_key"` within scanned `.json` (see FR2 walk) | content |
| DigitalOcean token | `~/.config/doctl/config.yaml` | content:`access-token:` |
| Terraform Cloud token | `~/.terraform.d/credentials.tfrc.json`, `~/.terraformrc` | exists / content:`credentials` |
| GitHub CLI token | `~/.config/gh/hosts.yml` | content:`oauth_token:` |
| GitLab CLI token | `~/.config/glab-cli/config.yml` | content:`token:` |
| npm token | `~/.npmrc` | content:`_authToken=.+` |
| Yarn token | `~/.yarnrc.yml` | content:`npmAuthToken` |
| PyPI password/token | `~/.pypirc` | content:`^[[:space:]]*password` |
| pip URL creds | `~/.config/pip/pip.conf` | content:`://[^/[:space:]]+:[^@/[:space:]]+@` |
| RubyGems key | `~/.gem/credentials` | exists |
| Cargo token | `~/.cargo/credentials.toml` | exists |
| Composer auth | `~/.config/composer/auth.json` | exists |
| Maven server password | `~/.m2/settings.xml` | content:`<password>` |
| NuGet password | `~/.config/NuGet/NuGet.Config` | content:`(ClearTextPassword\|<add key="Password")` |
| Docker registry auth | `~/.docker/config.json` | content:`"auth":` **and not** content:`(credsStore\|credHelpers)` |
| kubeconfig | `~/.kube/config` | content:`(client-key-data:\|[[:space:]]token:)` |
| PostgreSQL | `~/.pgpass` | exists |
| MySQL | `~/.my.cnf` | content:`password[[:space:]]*=` |
| MySQL login-path | `~/.mylogin.cnf` | exists |
| Heroku/other in netrc | `~/.netrc` | exists |

**Registry (noisy, tier = hygiene):**

| Kind | Location | Method |
|---|---|---|
| Gradle properties | `~/.gradle/gradle.properties` | content:`(password\|signing\.(key\|password)\|apiKey)` |
| Shell rc exports | `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshenv` | content:`export[[:space:]]+[A-Z_]*(TOKEN\|SECRET\|API_?KEY\|PASSWORD\|ACCESS_KEY)[A-Z_]*=` |
| `.env` files | bounded walk (FR2) | exists, excluding `*.example`/`*.sample`/`*.template` |

**Registry (tier = info):**

| Kind | Location | Method |
|---|---|---|
| GPG private keys | `~/.gnupg/private-keys-v1.d/` | directory non-empty |

**Reporting:** each match emits one finding via the existing `print_warn` (security/hygiene) or `print_info` (info), tagged with the v0.6.0 `set_tier`. The message contains the kind and the absolute path. The message MUST NOT contain any line, token, or value read from the file. For `content` matches, only `grep -q` (quiet) is used — matched text is never captured.

**Obfuscated-vs-plaintext wording:** entries that are encoded rather than literally plaintext (`~/.docker/config.json` base64, `~/.mylogin.cnf`, gcloud `*.db`) use the phrase "recoverable by any local process" rather than "plaintext."

This registry replaces and subsumes the current `audit_credential_hygiene` checks (`.git-credentials`, `.netrc`, `.npmrc`, `.pypirc`); those four are represented above and the old function is removed to avoid double-reporting.

### FR2 — Bounded `.env` / scanned-JSON walk

- A single `find` pass over `$HOME` discovers `.env` and `.env.*` files (excluding `.env.example`, `.env.sample`, `.env.template`) and, for the GCP service-account `content` rule, `*.json` candidates.
- **Depth:** `--scan-depth N` (default `2`) means files whose **parent directory is at most N levels below `$HOME`**. `$HOME/.env` = level 0; `$HOME/projects/.env` = level 1; `$HOME/projects/<repo>/.env` = level 2. Implemented as `find "$HOME" -maxdepth $((N + 1)) ...`.
- The current working directory is always scanned at its own root (depth 0) even if outside the home subtree, so a developer running inside a checked-out repo sees its `.env`.
- **Pruning (performance + noise):** the walk prunes, and does not descend into: `node_modules`, `.git`, `vendor`, `.cache`, `.cargo`, `.rustup`, `.npm`, `Library` (macOS), `.Trash`, `go/pkg`, `.terraform`, any directory beginning with a dot at depth ≥ 2 except those explicitly in the registry. Symlinks are never followed.
- The set of pruned directories and the active depth are printed once as an `[INFO]` line ("scanned ~/ to depth N; skipped node_modules, …") so coverage limits are explicit (v0.6.0 "no silent caps" principle).
- `find` stderr (permission-denied on unreadable subtrees) is suppressed; unreadable directories are silently skipped (they can't hold *our* user's readable secrets anyway).

### FR3 — Permission audit and `chmod 600` apply

- For every file finding (FR1), compute its mode via a portable helper (`stat -c '%a'` on Linux, `stat -f '%Lp'` on macOS). If `mode & 0077 != 0` (any group or other bit set), record a permission finding at **hygiene** tier: "<path> is mode <NNN> (group/other readable)".
- In the **apply** phase, the script offers to fix all flagged files: `chmod 600 <file>` each.
  - Interactive: a single grouped prompt listing the files, default **Yes** (this is safe hardening, not destructive).
  - `-y` mode: applied automatically (additive hardening; consistent with `-y` applying other secure defaults, and distinct from the never-in-`-y` *deletion* rule).
- `chmod` is guarded: if a target is not owned by the current user or not writable, it is skipped with a `[WARN]` and the script continues (must not abort under `errexit`). Directories (e.g. `~/.gnupg/private-keys-v1.d/`) are not chmod'd by this feature.
- In `--audit` mode no `chmod` is offered (read-only).

### FR4 — 1Password migration advisor

- Runs after the inventory, in both `--audit` (print-only) and apply phases.
- Detects `op` via `command -v op`. It does **not** call `op` or require a session.
- For each distinct finding kind present, prints a tailored next step:
  - **Shell-plugin CLIs** (`aws`→`gh`→`glab`→`terraform`→`vault`→`stripe`→`openai`, per a curated lookup): print `op plugin init <cli>` plus the one-line "then delete the plaintext file" follow-up.
  - **Config-file CLIs** (kubeconfig, docker, npm, pypi, netrc, pgpass, maven, cargo, composer, rubygems, gcloud): print the Shape-C `op inject -i <file>.tpl -o <file>` / `op run` pattern with a concrete example for that file, marked `‡ idiomatic — confirm with op --help`.
  - **Generic `.env`/dotfile tokens:** print the Shape-D pattern (`op run --env-file` with `op://` references, or 1Password Environments import).
  - **SSH/GPG keys:** point to the agent path (cross-reference the v0.7 agent-backed-keys feature) rather than duplicating it.
- If `op` is **not** installed: print a single install pointer (`https://developer.1password.com/docs/cli/get-started/`) and the generic principle, then the per-finding steps still print (they're the user's eventual path). The advisor prints nothing when the inventory found nothing.
- **Gitignore cross-reference (Should Have):** for each file finding, if `core.excludesFile` is configured and the file's basename pattern is present there, append "(also gitignored ✓)"; otherwise, for committable patterns, append a hint to add it. Uses the existing global-gitignore the script manages.

### FR5 — CLI flag

- New flag `--scan-depth N`: non-negative integer, default 2. Invalid values (non-integer, negative) → `die` with a usage message.
- Documented in `usage()` and `--help`. Composes with `--audit` and `-y`.
- All other invocation behavior unchanged.

## Edge Cases & Error States

### Input Boundaries
| Condition | Expected Behavior |
|---|---|
| No credentials found anywhere | Inventory prints a single `[OK]` "No plaintext dev credentials detected"; advisor prints nothing |
| `$HOME` unset or not a directory | Skip the walk-based checks; fixed-path checks that resolve still run; print `[INFO]` that home-scan was skipped |
| Detected file unreadable (EACCES) | Report as a finding by `exists`; skip its `content`/permission classification; never abort |
| Detected file is a symlink | Report the link path; do not follow for `content`; `chmod` is skipped for symlinks with a `[WARN]` |
| `.env.example`/`.sample`/`.template` | Excluded — not a finding |
| `--scan-depth 0` | Only `$HOME/.env` (parent at level 0) and cwd root are scanned |
| Enormous home tree | Bounded by `maxdepth` + prune list; see performance target |

### Failure Modes
| Failure | Response |
|---|---|
| `find` errors on unreadable subtrees | stderr suppressed; those dirs skipped; walk continues |
| `stat` unavailable / unexpected output | Permission check for that file skipped with `[WARN]`; finding still reported |
| `chmod` target not owned/writable | Skip with `[WARN]`; continue (no `errexit` abort) |
| `op` absent | Advisor degrades to install pointer + generic steps |
| Platform is neither macOS nor Linux | Already `die`'d by existing `detect_platform`; N/A |

### Security Boundaries
| Threat | Mitigation |
|---|---|
| Secret value leaks into terminal/logs | Output is path + kind only; `content` checks use `grep -q`; no file contents captured into variables that are printed |
| Feature writes a findings file that itself leaks | No findings are written to disk; all output to stderr like the rest of the audit |
| `chmod` used to weaken perms | Only ever `chmod 600` (tightening); never loosens; never recurses; never targets directories |
| Walk follows a malicious symlink out of `$HOME` | Symlinks never followed during the walk |
| Advisor command injection via crafted path | Paths are printed inside single-quoted examples; never `eval`'d or executed |

## Non-Functional Requirements

### Performance
- Full run (all fixed-path checks + bounded `.env`/JSON walk at default depth, on a home directory of up to ~200k files dominated by pruned dirs like `node_modules`) completes the inventory section in **< 3s** on a 2020-class laptop. Guaranteed by `maxdepth` + the prune list + no-symlink-follow; not by scanning fewer files opportunistically.
- The walk is a **single** `find` invocation, not one per pattern.

### Security
- No secret value is ever read into a shell variable that reaches stdout/stderr.
- `chmod` only tightens, only on regular files owned by the user.

### Testing
- BATS unit tests in the existing isolated-`$HOME` harness: one test per detection method class (exists, content-match, content-no-match, obfuscated wording), tier assignment, permission finding + `chmod` apply (and the not-owned skip path), `.env` depth boundary (level 0/1/2/3 with default and with `--scan-depth`), prune behavior, `--scan-depth` validation, advisor output with/without `op` on PATH (stub `op`), no-value-leak assertion (grep the output for a planted secret value and assert absent).
- `--audit` exit-code test: a security-tier finding → exit 2; only-hygiene/info findings → exit 0.
- Portability: tests pass on bash 3.2 and 5.x; `stat` helper covered on both `-c` and `-f` forms.
- `shellcheck` clean; no suppressed warnings.

## Implementation Phases

Each phase is independently shippable and testable.

**Phase 1 — Inventory core.** FR1 registry for all fixed-path entries (no walk yet); tiering; output discipline (path+kind, `grep -q`); fold in and remove the old `audit_credential_hygiene`. Tests for each method class and tier.

**Phase 2 — Bounded walk.** FR2 `.env`/JSON discovery, `--scan-depth` (FR5), prune list, coverage `[INFO]` line, cwd-root scan. Depth-boundary and prune tests.

**Phase 3 — Permission fix.** FR3 portable mode check + grouped `chmod 600` apply (interactive default-Yes, `-y` auto), not-owned/symlink skip. Apply and skip-path tests.

**Phase 4 — 1Password advisor.** FR4 per-kind tailored steps, `op`-presence tailoring, shell-plugin lookup, gitignore cross-reference. Advisor-output tests with stubbed `op`.

**Phase 5 — Docs.** REASONING.md "Plaintext Secret Inventory" section (the five solution shapes, why audit-only + chmod-only, the depth/prune rationale); README "Moving secrets into 1Password" walkthrough. CHANGELOG + version bump to 0.8.0.

## Pre-Mortem

### Likely Failure Modes
| Failure | Why It Could Happen |
|---|---|
| Users disable/ignore the section | False positives in the security tier (esp. `gradle.properties`, shell-rc, `.env`) make `--audit` perpetually red |
| The walk is slow or hangs | Home dir with millions of files; following symlinks; per-pattern find invocations |
| A secret value leaks into output or a log | Switching a `grep -q` to `grep` for "context"; capturing a matched line into the message |
| `chmod` aborts the run or breaks a shared file | `errexit` + a not-owned file; or a file intentionally group-readable for a shared service account |
| Advisor gives a wrong/broken command | `op` CLI syntax drifts; idiomatic `op inject` examples don't match a specific tool |
| Scope creep | "While we're here" Bitwarden/keychain/browser additions balloon the diff |

### Mitigations
- Users ignore → **Addressed:** strict existence-vs-content tiering; noisy detectors live in `hygiene`/`info`, never `security`; only `security` gates `--audit` exit (FR1, FR4, acceptance AC-7).
- Slow walk → **Addressed:** single `find`, `maxdepth`, prune list, no symlink follow, < 3s target (FR2, Performance).
- Value leak → **Addressed:** path+kind-only output, `grep -q` mandated, no-leak test (FR1, Security, Testing).
- `chmod` abort/break → **Addressed:** guarded chmod, skip not-owned/symlink, never aborts; default-Yes but only tightens (FR3). Group-readable-on-purpose is an **accepted risk** — the user can decline interactively; `-y` users opted into hardening defaults.
- Wrong advisor command → **Addressed:** shell-plugin commands are verified; config-file examples marked `‡ idiomatic — confirm with op --help` (FR4); re-verify at implementation.
- Scope creep → **Addressed:** Non-Goals (Bitwarden/keychain/browser/deletion/op-driving explicitly excluded).

## Acceptance Criteria

### Must Have

- [ ] **AC-1: Detects a plaintext AWS credentials file**
  - Given: `~/.aws/credentials` contains `aws_secret_access_key=…`
  - When: the inventory runs
  - Then: a `security`-tier finding naming the kind ("AWS static keys") and the path is printed; the secret value does not appear in output.

- [ ] **AC-2: Content-gated file with no secret is not flagged**
  - Given: `~/.npmrc` exists but contains no `_authToken=`
  - When: the inventory runs
  - Then: no npm finding is printed.

- [ ] **AC-3: No secret value ever appears in output**
  - Given: any detected file containing a unique sentinel value `SENTINEL_LEAK_CHECK`
  - When: inventory + advisor run and output is captured
  - Then: the captured output does not contain `SENTINEL_LEAK_CHECK`.

- [ ] **AC-4: Group/world-readable secret is flagged and fixed**
  - Given: `~/.pgpass` exists with mode 644
  - When: apply phase runs (interactive accept, or `-y`)
  - Then: a hygiene permission finding is printed and the file's mode becomes `600`.

- [ ] **AC-5: `chmod` skips a non-owned file without aborting**
  - Given: a detected file the current user cannot `chmod`
  - When: apply phase runs
  - Then: a `[WARN]` is printed, the file is unchanged, and the script continues to completion (exit 0/expected).

- [ ] **AC-6: `.env` depth default and override**
  - Given: `.env` files at `$HOME/.env`, `$HOME/projects/app/.env` (level 2), and `$HOME/a/b/c/.env` (level 3)
  - When: run with default depth; then with `--scan-depth 3`
  - Then: default surfaces the first two and not the level-3 file; `--scan-depth 3` additionally surfaces the level-3 file.

- [ ] **AC-7: Audit exit reflects security tier only**
  - Given: the only findings are `.env` files and a group-readable mode (hygiene) — no security-tier findings
  - When: `git-harden.sh --audit`
  - Then: exit code is 0.
  - And given: a `~/.pgpass` exists (security) → `--audit` exit code is 2.

- [ ] **AC-8: 1Password step printed per finding, tailored to `op` presence**
  - Given: `~/.aws/credentials` is detected and `op` is on PATH
  - When: the advisor runs
  - Then: output includes `op plugin init aws`.
  - And given: `op` is not on PATH → output includes the install pointer URL and still prints the per-finding step.

- [ ] **AC-9: Walk is bounded and explicit**
  - Given: a home dir containing `node_modules` with a nested `.env`
  - When: the walk runs
  - Then: the nested `node_modules/.env` is not reported, and an `[INFO]` line names the depth and pruned directories.

- [ ] **AC-10: `--scan-depth` validation**
  - Given: `--scan-depth -1` or `--scan-depth abc`
  - When: the script starts
  - Then: it `die`s with a usage error and non-zero exit.

### Should Have

- [ ] **AC-11: Obfuscated entries use accurate wording**
  - Given: `~/.docker/config.json` with `"auth":` and no `credsStore`
  - Then: the finding says "recoverable by any local process," not "plaintext."

- [ ] **AC-12: Gitignore cross-reference**
  - Given: a detected `.env` and a managed `core.excludesFile` containing `.env`
  - Then: the finding notes it is also gitignored.

### Could Have

- [ ] **AC-13:** Advisor groups findings by 1Password mechanism (plugin / config-template / env) rather than one block per file.
- [ ] **AC-14:** A `.bak` rename offered as an alternative to `chmod` is **not** in scope (kept as Won't, see below) — but a "skip this file" per-file choice in the interactive prompt MAY be added.

### Won't Have (this spec)

- Bitwarden advisor track.
- Running any `op` command on the user's behalf.
- Deleting, renaming, or backing up credential files.
- OS keychain / Secret Service / browser password store scanning.
- Recursive unbounded `$HOME` scanning or scanning outside `$HOME`+cwd.
- Secret rotation or credential-validity checks.

## Dependencies

- v0.6.0 audit-tier machinery (`set_tier`, per-tier counters, security-only `--audit` exit).
- Existing isolated-`$HOME` BATS harness.
- A portable `file_mode` helper (new; `stat -c`/`stat -f`).
- The global-gitignore management already in the script (for AC-12).

## Open Questions

> Should be empty before implementation.

- None outstanding. (Resolved with maintainer: 1Password-only; `chmod 600` is an applied action, default-Yes interactive and auto in `-y`; `.env` default depth 2 with `--scan-depth` override.)
