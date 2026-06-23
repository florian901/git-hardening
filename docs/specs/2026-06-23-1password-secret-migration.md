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

**Detection methods (exhaustive — four):**
- `exists` — file is present (the file's existence alone implies a credential).
- `content:<ERE>` — file is present **and** the scanner (FR1.2) matches `<ERE>` (the file is config that *may* embed a secret).
- `dir-nonempty:<dir>` — directory exists and contains at least one entry (used for `~/.gnupg/private-keys-v1.d/`). No file contents are read.
- `json-marker:<file>` — file matches **two** ordered scanner passes: first `"type"[[:space:]]*:[[:space:]]*"service_account"`, then (only if the first matched) `"private_key"`. Used for GCP service-account JSON discovered by the FR2 walk. Two `grep -q` passes, short-circuited on the first miss; neither captures content (FR1.1).

Every detected file (by any method) is additionally subject to the FR3 permission check.

#### FR1.1 — Minimal-read discipline (mandatory)

Scanning files for secrets is itself a sensitive act. The script must ascertain *presence* while reading and holding as little of the secret as technically possible. This constrains every `content` detection:

1. **Match the key/marker, not the value.** A detection regex MUST anchor on the credential's identifying key or marker (`aws_secret_access_key`, `_authToken=`, `oauth_token:`) and may match **at most one byte** of the value — solely to prove the value is non-empty. It MUST NOT match the full value.
2. **No value-spanning constructs.** Detection regexes MUST NOT use `.+`, `.*`, `{n,}`, back-references, or capture groups applied to the value region. The "is there a value" proof is a single-character class (e.g. `_authToken=.` or `_authToken=[^[:space:]]`), never `_authToken=.+`.
3. **Presence, never validation.** The script does not verify a token "looks real" (length, charset, checksum) — that would require reading the whole value. Presence of the key with a non-empty value is sufficient to warn.
4. **Quiet match, discarded output.** The scanner runs in quiet/first-match mode (FR1.2). The matched text is never captured into a shell variable, command substitution, here-string, or printed. No `sed`/`awk`/`cut`/parameter-expansion is used to extract a value.
5. **First-match short-circuit.** Scanning stops at the first match (`rg -q` / `grep -qm1`), so at most one matching line is ever examined.

**Acknowledged technical floor:** both `rg` and `grep` read input a line at a time, so the *line* containing a secret transiently exists inside the **scanner's** process buffer (never the bash process) for the duration of one match. This is the minimum achievable with line-oriented tooling; the guarantee this spec makes is that **the script (the bash process) never captures, stores, or emits the value**, and that detection patterns never deliberately consume past the first value byte.

**Documented exception — URL-embedded credentials.** Detecting credentials inside a URL (`pip.conf` `https://user:pass@host`) inherently requires the regex to span from `:` to `@`, i.e. across the password. This single registry entry is exempt from rule 1; it still obeys rules 2–5 (no capture, quiet match, discarded, `LC_ALL=C`). It is **security**-tier and worded as "credentials embedded in a URL" — it is genuinely plaintext, not obfuscated, so the "recoverable by any local process" phrasing (which is reserved for base64/SQLite-obfuscated entries) does not apply to it.

#### FR1.2 — Scanner abstraction: ripgrep preferred, grep fallback

All `content` detection goes through a single internal helper (e.g. `scan_quiet <ere> <file>`), never a bare `grep`/`rg` call at the call sites. The helper:

1. **Prefers ripgrep.** If `rg` is on `PATH`, use `rg --quiet --max-count=1 --no-config -e '<ere>' -- '<file>'` (and `--ignore-case` for the case-insensitive heuristic). `--no-config` prevents a user `RIPGREP_CONFIG_PATH` from altering matching; `-e`/`--` guard against patterns/paths that begin with `-`.
2. **Falls back to grep.** Otherwise use `grep -qElm1 -- '<ere>' '<file>'` (`-E` ERE, `-l`/`-q` quiet, `-m1` first match). On platforms where `grep` lacks `-m` the helper drops it but still relies on `-q` to exit at first match.
3. **Returns only a status** — 0 = matched, 1 = no match, ≥2 = error. The matched line is discarded by both engines (`-q`); the helper never emits it. This is the single place FR1.1 is enforced, so an audit of one function proves the whole feature's read discipline.
4. **`errexit`/`pipefail` safety (critical).** The script runs under `set -o errexit -o pipefail`. A no-match exit (1) is the **common, expected** path (most content-gated files contain no secret — AC-2). Therefore: every `content` detection MUST be written as an `if scan_quiet …; then` condition or guarded with `|| true`/`|| return`; it MUST NOT appear as a bare statement or as a non-final pipeline stage, either of which would abort the run on the routine no-match. The helper itself returns the status without letting a no-match propagate as a fatal error. This is the single most likely implementation regression — AC-18 tests it directly.
5. **`LC_ALL=C` for all detection scans.** Both engines are invoked with `LC_ALL=C` (equivalently `LC_CTYPE=C`). This (a) makes `[[:space:]]`/`[[:alnum:]]` and case-folding behave identically across GNU and BSD, and (b) avoids locale-dependent "invalid byte" diagnostics that could echo buffer fragments. The URL-embedded exception below especially relies on this.

**Regex-dialect constraint (mandatory).** Because the same pattern string is fed to *either* ripgrep (Rust `regex` crate) *or* POSIX ERE (`grep -E`), every registry pattern MUST use only the common subset valid and **semantically identical** in both:
- Allowed: literals, `.`, alternation `(a|b)`, quantifiers `? * +` and `{n,m}` (subject to FR1.1 — no value-spanning quantifiers), grouping `(...)`, POSIX classes `[[:space:]]` / `[[:alnum:]]`, bracket expressions `[^@/]`, anchors `^` `$`.
- **Forbidden** (dialect-divergent or PCRE-only): `\b`, `\d`, `\w`, `\s`, `\K`, lookaround, non-greedy `*?`, named groups, back-references. (Several are valid in `rg` but not in POSIX ERE — banning them keeps one pattern string correct in both.)
- Patterns are matched **per line** by both engines (default), so no multi-line constructs.
- A test (AC-16) runs every registry pattern through both `rg` and `grep -E` against the same fixtures and asserts identical match/no-match verdicts.

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
| npm token | `~/.npmrc` | content:`_authToken=[^[:space:]]` |
| Yarn token | `~/.yarnrc.yml` | content:`^[[:space:]]*npmAuthToken:[[:space:]]*[^[:space:]#]` |
| PyPI password/token | `~/.pypirc` | content:`^[[:space:]]*password[[:space:]]*=[[:space:]]*[^[:space:]]` |
| pip URL creds | `~/.config/pip/pip.conf` | content:`://[^/[:space:]]+:[^@/[:space:]]+@` *(URL-embedded exception, FR1.1)* |
| RubyGems key | `~/.gem/credentials` | exists |
| Cargo token | `~/.cargo/credentials.toml` | exists |
| Composer auth | `~/.config/composer/auth.json` | exists |
| Maven server password | `~/.m2/settings.xml` | content:`<password>[^<$%]` (literal value byte; excludes empty `<password></password>` and `${env...}`/`%VAR%` templates) |
| Docker registry auth | `~/.docker/config.json` | content:`"auth":[[:space:]]*"[^"]` **and not** content:`(credsStore\|credHelpers)` (non-empty auth string only) |
| kubeconfig | `~/.kube/config` | content:`(client-key-data:[[:space:]]*[^[:space:]]\|[[:space:]]token:[[:space:]]*[^[:space:]])` |
| PostgreSQL | `~/.pgpass` | exists |
| MySQL | `~/.my.cnf` | content:`password[[:space:]]*=` |
| MySQL login-path | `~/.mylogin.cnf` | exists |
| Heroku/other in netrc | `~/.netrc` | exists |

**Registry (noisy, tier = hygiene):**

| Kind | Location | Method |
|---|---|---|
| NuGet password | `~/.config/NuGet/NuGet.Config` | content:`ClearTextPassword` (the `<add key="Password" value="%ENV%">` form is too often env-templated for security tier) |
| Gradle properties | `~/.gradle/gradle.properties` | content:`(password\|signing\.(key\|password)\|apiKey)` |
| Shell rc / dotfile exports | `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshenv` | content:`$SECRET_ASSIGN_ERE` (see below) |
| `.env` files | bounded walk (FR2) | exists, excluding `*.example`/`*.sample`/`*.template` |

**Generic secret-assignment heuristic (`$SECRET_ASSIGN_ERE`).** A single shared ERE catches `FOO_TOKEN=…`, `GIT_TOKEN="…"`, `export API_KEY=…` style assignments. It is **hygiene-tier only** (never `security`) and is applied **only to the files the script already reads** (shell rc above; optionally as a `.env` content classifier) — it is **not** a broad machine-wide scan.

```
(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)[[:space:]]*[:=][[:space:]]*["']?[^[:space:]"'$]
```
Run case-insensitively via the FR1.2 scanner (`rg --ignore-case` / `grep -i`). Deliberate properties:
- **Adjacency-anchored to denoise.** The secret keyword must sit immediately before the `=`/`:` separator, so `SSH_KEY_PATH=`, `KEY_FILE=`, `KEY_ID=`, `TOKEN_NAME=`, `*_URL=`, `TOKENIZER=` do **not** match (the trailing word, not the keyword, abuts the `=`). `PUBLIC_KEY=` still matches (rare in rc files; acceptable at hygiene tier). Relies on the *absence* of `\b` (which is non-portable) — adjacency does the work instead.
- **FR1.1-compliant.** Keyword + separator + optional quote + **exactly one** non-space, non-quote value byte (proof of non-emptiness). Never spans the value. The user-suggested `.*_(TOKEN|KEY).*=".*` form is explicitly rejected: the trailing `.*` would read the whole secret (violates FR1.1) and the un-anchored `.*_` plus broad `KEY` would flood false positives.
- **Excludes `$`-references.** The final class is `[^[:space:]"'$]`, so `export GITHUB_TOKEN=$GH_TOKEN` (a reference, not a literal secret) does not match — only a literal value byte does.
- **No redundant branches.** `SECRET` already covers `SECRET_KEY`; only distinct keywords are listed.
- **Reporting wording.** Findings from this detector are worded "secret-shaped assignment in <file>", never "plaintext secret" — it is a heuristic, hygiene-tier signal.
- **Dialect-portable (FR1.2).** Common-subset constructs only; identical match under ripgrep and `grep -E`.

**Registry (tier = info):**

| Kind | Location | Method |
|---|---|---|
| GPG private keys | `~/.gnupg/private-keys-v1.d/` | directory non-empty |

**Reporting:** each match emits one finding via the existing `print_warn` (security/hygiene) or `print_info` (info). The message contains the kind and the absolute path. The message MUST NOT contain any line, token, or value read from the file. For `content`/`json-marker` matches, only the FR1.2 scanner (quiet, first-match) is used — matched text is never captured.

**Per-finding tier is explicit (not ambient).** The v0.6.0 `set_tier` global is *sticky*: it stays whatever the previous section set it to. Every finding here MUST call `set_tier <its-tier>` immediately before emitting, never relying on the ambient value. Because this section runs after others (which leave the tier at `security`), a forgotten `set_tier hygiene` would silently push `.env`/gradle noise into the `security` count and fail `--audit`. AC-19 is a regression test: a home dir with only hygiene/info findings must yield `TIER_SECURITY_ISSUES == 0`.

**Symlinks.** The walk uses `-type f` and does not follow links; fixed-path entries that are symlinks are reported as `exists` but their **content scan is gated by `[ ! -L "$f" ]`** — the scanner is never pointed at a symlink (which would read through to the target). `chmod` likewise skips symlinks (FR3).

**Obfuscated-vs-plaintext wording:** entries that are encoded rather than literally plaintext (`~/.docker/config.json` base64, `~/.mylogin.cnf`, gcloud `*.db`) use the phrase "recoverable by any local process" rather than "plaintext."

This registry replaces and subsumes the current `audit_credential_hygiene` checks (`.git-credentials`, `.netrc`, `.npmrc`, `.pypirc`); those four are represented above and the old function is removed to avoid double-reporting.

### FR2 — Bounded `.env` / scanned-JSON walk

- A single `find` pass over `$HOME` discovers `.env` and `.env.*` files (excluding `.env.example`, `.env.sample`, `.env.template`, `.env.dist`) and, for the GCP service-account `content` rule (FR1, `dir-nonempty`/`json-marker` method), `*.json` candidates.
- **Depth semantics (explicit, to remove ambiguity).** `--scan-depth N` (default `2`) means: scan files whose **parent directory is at most N levels below `$HOME`**. "Level" counts directory hops from `$HOME` to the file's parent. `find`'s own `-maxdepth` counts `$HOME` as 0 and the file itself as a level, so **file find-depth = parent-level + 1** and the implementation uses `-maxdepth "$((N + 1))"`:

  | File | parent-level | find-depth | surfaced at default N=2 (`-maxdepth 3`) | surfaced at N=3 (`-maxdepth 4`) |
  |---|---|---|---|---|
  | `$HOME/.env` | 0 | 1 | yes | yes |
  | `$HOME/projects/.env` | 1 | 2 | yes | yes |
  | `$HOME/projects/<repo>/.env` | 2 | 3 | yes | yes |
  | `$HOME/a/b/c/.env` | 3 | 4 | **no** | yes |

- **NUL-safe consumption (mandatory).** Because `IFS=$'\n\t'` and filenames may contain spaces/tabs/newlines, the walk MUST be consumed NUL-delimited: `find … -print0 | while IFS= read -r -d '' f; do …`. (Both GNU and BSD `find` support `-print0`.) No `for f in $(find …)`.
- **`find` predicate skeleton (BSD + GNU compatible).** `-maxdepth` is given first (BSD requires global options before predicates); prune directories are matched and `-prune`d **before** the file-match branch, using grouped `-o`:

  ```sh
  LC_ALL=C find "$HOME" -maxdepth "$((N + 1))" \
      \( -type d \( -name node_modules -o -name .git -o -name vendor \
            -o -name .cache -o -name .cargo -o -name .rustup -o -name .npm \
            -o -name Library -o -name .Trash -o -name .terraform -o -name pkg \) -prune \) \
      -o \( -type f \( -name '.env' -o -name '.env.*' \) -print0 \) \
      2>/dev/null
  ```
  (The JSON-candidate pass is a second branch / second invocation with the same prune set; symlinks are not followed because no `-L`/`-follow` is given and file matches use `-type f`.)
- **Prune list is a fixed allowlist** (the directory basenames above), not a "dot-dir at depth ≥ 2" heuristic — the heuristic was dropped as ambiguous and as conflicting with the JSON discovery. Anything outside the list within depth is scanned.
- **De-duplication.** Findings are keyed by canonical path (`realpath`/`cd&&pwd` fallback). The cwd scan (next bullet) and the `$HOME` walk can surface the same file; it is reported **once**.
- The current working directory is always scanned at its own root (its direct children, equivalent to depth 0) even if outside the home subtree, so a developer running inside a checked-out repo sees its `.env`.
- The active depth and the pruned-directory list are printed once as an `[INFO]` line ("scanned ~/ to depth N; skipped node_modules, …") so coverage limits are explicit (v0.6.0 "no silent caps" principle).
- `find` stderr (permission-denied on unreadable subtrees) is suppressed; unreadable directories are silently skipped (they can't hold *our* user's readable secrets anyway).

### FR3 — Permission audit and `chmod 600` apply

- For every file finding (FR1), compute its mode via a portable `file_mode` helper: `stat -c '%a' "$f"` on Linux, `stat -f '%Lp' "$f"` on macOS (BSD). Expected output is a 3- or 4-digit string (e.g. `644`, `0600`, `4755`); the helper validates it against `^[0-7]{3,4}$` and, on anything else, returns failure so the caller skips the check with a `[WARN]` (per the failure table).
- **Octal masking (critical correctness).** The mode string MUST be interpreted as octal before masking. `stat -f '%Lp'` (macOS) returns no leading zero, so `$(( 644 & 077 ))` would treat `644`/`077` as **decimal** and yield a wrong result silently. The implementation MUST force base 8: strip any leading zeros then `(( 8#${mode} & 8#77 ))` (using only the low 3 octal digits for the permission bits). A non-zero result means a group or other bit is set → record a **hygiene**-tier finding: "<path> is mode <NNN> (group/other readable)". A BATS test covers a macOS-style no-leading-zero mode and a 4-digit (setuid-style) mode.
- In the **apply** phase, the script offers to fix all flagged files: `chmod 600 <file>` each.
  - Interactive: a single grouped prompt listing the files, default **Yes** (this is safe hardening, not destructive).
  - `-y` mode: applied automatically (additive hardening; consistent with `-y` applying other secure defaults, and distinct from the never-in-`-y` *deletion* rule).
- `chmod` is guarded: if a target is not owned by the current user or not writable, it is skipped with a `[WARN]` and the script continues (must not abort under `errexit`). Directories (e.g. `~/.gnupg/private-keys-v1.d/`) are not chmod'd by this feature.
- In `--audit` mode no `chmod` is offered (read-only).

### FR4 — 1Password migration advisor

- Runs after the inventory, in both `--audit` (print-only) and apply phases.
- Detects `op` via `command -v op`. It does **not** call `op` or require a session.
- For each distinct finding kind present, prints a tailored next step:
  - **Shell-plugin CLIs** (curated lookup, single source of truth shared with the research doc: `aws`, `gh`, `glab`, `terraform`, `vault`, `stripe`, `openai`, `vercel`, `circleci`): print `op plugin init <cli>` plus the one-line "then delete the plaintext file" follow-up. The lookup is a fixed table in the script; adding a CLI means adding a row.
  - **Config-file CLIs** (kubeconfig, docker, npm, pypi, netrc, pgpass, maven, cargo, composer, rubygems, gcloud): print the Shape-C `op inject -i <file>.tpl -o <file>` / `op run` pattern with a concrete example for that file, marked `‡ idiomatic — confirm with op --help`.
  - **Generic `.env`/dotfile tokens:** print the Shape-D pattern (`op run --env-file` with `op://` references, or 1Password Environments import).
  - **SSH/GPG keys:** point to the agent path (cross-reference the v0.7 agent-backed-keys feature) rather than duplicating it.
- If `op` is **not** installed: print a single install pointer (`https://developer.1password.com/docs/cli/get-started/`) and the generic principle, then the per-finding steps still print (they're the user's eventual path). The advisor prints nothing when the inventory found nothing.
- **Gitignore cross-reference (Should Have):** for each file finding, if `core.excludesFile` is configured and the file's basename pattern is present there, append "(also gitignored ✓)"; otherwise, for committable patterns, append a hint to add it. Uses the existing global-gitignore the script manages.

### FR5 — CLI flag

- New flag `--scan-depth N`: non-negative integer, default 2.
- **Validation order (under `set -u`/`errexit`).** Validate as a **string regex first** — `[[ "$N" =~ ^[0-9]+$ ]]` — and `die` with a usage message on failure. Do **not** feed an unvalidated value into `(( … ))`, because `(( abc >= 0 ))` throws "invalid arithmetic operator" and aborts non-gracefully instead of the intended clean `die`.
- Documented in `usage()` and `--help`. Composes with `--audit` and `-y`.
- All other invocation behavior unchanged.

## Edge Cases & Error States

### Input Boundaries
| Condition | Expected Behavior |
|---|---|
| No credentials found anywhere | Inventory prints a single `[OK]` "No plaintext dev credentials detected"; advisor prints nothing |
| `$HOME` unset | Unreachable here: the script's `readonly SSH_DIR="${HOME}/.ssh"` etc. load under `set -u` and already `die` at startup if `$HOME` is unset. No additional handling needed; noted so an implementer doesn't add dead code. |
| Detected file unreadable (EACCES) | Report as a finding by `exists`; skip its `content`/permission classification; never abort |
| Detected file is a symlink | Report the link path; content scan gated by `[ ! -L ]` (never read through the link); `chmod` skipped for symlinks with a `[WARN]` |
| `.env.example`/`.sample`/`.template` | Excluded — not a finding |
| `--scan-depth 0` | Only `$HOME/.env` (parent at level 0) and cwd root are scanned |
| Enormous home tree | Bounded by `maxdepth` + prune list; see performance target |

### Failure Modes
| Failure | Response |
|---|---|
| Scanner finds no match (exit 1) under `set -euo pipefail` | Helper invoked only in a condition / guarded with `|| true`; exit 1 never aborts the run (FR1.2.4) |
| `rg` absent | Scanner transparently falls back to `grep -qElm1`; identical verdicts (FR1.2) |
| `rg` present but user `RIPGREP_CONFIG_PATH` set | `--no-config` neutralizes it so matching is deterministic (FR1.2.1) |
| `find` errors on unreadable subtrees | stderr suppressed; those dirs skipped; walk continues |
| `stat` unavailable / unexpected output | Permission check for that file skipped with `[WARN]`; finding still reported |
| `chmod` target not owned/writable | Skip with `[WARN]`; continue (no `errexit` abort) |
| `op` absent | Advisor degrades to install pointer + generic steps |
| Platform is neither macOS nor Linux | Already `die`'d by existing `detect_platform`; N/A |

### Security Boundaries
| Threat | Mitigation |
|---|---|
| Secret value leaks into terminal/logs | Output is path + kind only; `content` checks use `grep -q`; no file contents captured into variables that are printed |
| Script holds more of a secret in memory than needed | FR1.1 minimal-read discipline: patterns match key/marker + ≤1 value byte; no `.+`/`.*`/capture groups; scanner runs quiet/first-match (FR1.2); value never enters a shell variable. (Floor: the scanner's own per-line buffer — see FR1.1.) |
| Feature writes a findings file that itself leaks | No findings are written to disk; all output to stderr like the rest of the audit |
| `chmod` used to weaken perms | Only ever `chmod 600` (tightening); never loosens; never recurses; never targets directories |
| Walk follows a malicious symlink out of `$HOME` | Symlinks never followed during the walk |
| Advisor command injection via crafted path | Paths in printed examples are escaped with `printf %q` (single-quoting alone breaks on a path containing a `'`, e.g. `~/projects/o'brien/.env`); examples are display-only, never `eval`'d or executed |

## Non-Functional Requirements

### Performance
- Full run (all fixed-path checks + bounded `.env`/JSON walk at default depth, on a home directory of up to ~200k files dominated by pruned dirs like `node_modules`) completes the inventory section in **< 3s** on a 2020-class laptop. Guaranteed by `maxdepth` + the prune list + no-symlink-follow; not by scanning fewer files opportunistically.
- The walk is a **single** `find` invocation, not one per pattern.

### Security
- No secret value is ever read into a shell variable that reaches stdout/stderr.
- **Minimal-read (FR1.1):** detection matches the credential key/marker plus at most one value byte; no detection regex spans the full value; no value is captured by the bash process. The only acknowledged floor is grep's transient one-line process buffer.
- `chmod` only tightens, only on regular files owned by the user.

### Testing
- BATS unit tests in the existing isolated-`$HOME` harness: one test per detection method class (exists, content-match, content-no-match, dir-nonempty, json-marker two-pass, obfuscated wording), tier assignment, permission finding + `chmod` apply (and the not-owned skip path), `.env` depth boundary (parent-level 0/1/2/3 with default and `--scan-depth`), prune behavior, `--scan-depth` validation (rejects `abc`/`-1` cleanly, no arithmetic abort), advisor output with/without `op` on PATH (stub `op`), no-value-leak assertion (grep output for a planted sentinel and assert absent).
- **Regression tests from the pre-implementation review:** AC-18 (no-match never aborts under `errexit`/`pipefail`); AC-19 (tier does not leak from a prior section); AC-16/17 (rg↔grep parity and fallback); a filename with a space/newline/tab in a scanned `.env` path (NUL-safe consumption); `file_mode` octal masking on a macOS-style no-leading-zero mode and a 4-digit mode; symlink content-scan gate (`[ ! -L ]`).
- `--audit` exit-code test: a security-tier finding → exit 2; only-hygiene/info findings → exit 0.
- Portability: tests pass on bash 3.2 and 5.x; `stat` helper covered on both `-c` and `-f` forms; the FR1.2 scanner exercised with `rg` present **and** absent (fallback), and every pattern checked for rg↔grep parity (AC-16).
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
| The scanner reads/holds more of a secret than needed | A detection pattern uses `.+`/a capture group and spans the whole value; a future tweak pipes a matched line through `sed`/`awk` |
| `chmod` aborts the run or breaks a shared file | `errexit` + a not-owned file; or a file intentionally group-readable for a shared service account |
| Advisor gives a wrong/broken command | `op` CLI syntax drifts; idiomatic `op inject` examples don't match a specific tool |
| Scope creep | "While we're here" Bitwarden/keychain/browser additions balloon the diff |

### Mitigations
- Users ignore → **Addressed:** strict existence-vs-content tiering; noisy detectors live in `hygiene`/`info`, never `security`; only `security` gates `--audit` exit (FR1, FR4, acceptance AC-7).
- Slow walk → **Addressed:** single `find`, `maxdepth`, prune list, no symlink follow, < 3s target (FR2, Performance).
- Value leak → **Addressed:** path+kind-only output, `grep -q` mandated, no-leak test (FR1, Security, Testing).
- Over-reading a secret → **Addressed:** FR1.1 minimal-read discipline — key/marker + ≤1 byte patterns, banned value-spanning constructs (enforced by AC-15 static check), scanner quiet/first-match (FR1.2), no capture. The scanner's one-line buffer is an **accepted, honestly-documented technical floor** (AC-15 explicitly disclaims a bytes-read bound).
- No-match aborts the run → **Addressed:** FR1.2.4 mandates condition/`|| true` form; AC-18 regression test.
- macOS-only misbehavior (octal mask, BSD find, stat format) → **Addressed:** FR3 forced base-8 masking, FR2 BSD-compatible find skeleton + `-print0`, `file_mode` format validation; portability tests on bash 3.2 + both `stat` forms.
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

- [ ] **AC-15: Minimal-read discipline is enforced**
  - Given: the detection registry as implemented in the script
  - When: a static check greps the detection patterns
  - Then: no `content` pattern contains `.+`, `.*`, `{`, or a capture group spanning the value; all run via the FR1.2 scanner (quiet, first-match) and none feeds a matched line into `sed`/`awk`/`cut`/a captured variable (except the FR1.1 URL-embedded exception).
  - And given: an `~/.npmrc` whose `_authToken=` value is 100 KB long
  - When: the inventory runs
  - Then: it reports the npm finding, and the planted value does not appear anywhere in captured output (per AC-3).
  - Note: this AC does **not** claim a bounded number of bytes is read from the file. Both `rg` and `grep` read line-by-line, so a single-line secret of length N is fully pulled into the *scanner's* buffer regardless of `-m1` (which stops at the first matching *line*, not byte). The guarantee is scoped to the bash process never capturing the value, plus FR1.1's no-value-spanning pattern rule — not a file-read bound. (See FR1.1 "Acknowledged technical floor.")

- [ ] **AC-16: Detection patterns are dialect-portable (rg ↔ grep parity)**
  - Given: the full registry of `content` patterns and a fixture set of matching and non-matching lines
  - When: each pattern is evaluated with both `rg --max-count=1` and `grep -E` against each fixture
  - Then: every pattern yields the **same** match/no-match verdict under both engines; no pattern contains a forbidden construct (`\b \d \w \s` lookaround, non-greedy, back-references) per a static check.

- [ ] **AC-17: ripgrep preferred, grep fallback, identical results**
  - Given: a home dir with a detectable secret
  - When: the inventory runs once with `rg` on `PATH` and once with `rg` removed from `PATH`
  - Then: both runs produce the identical set of findings; the run without `rg` uses `grep` (observable via a stubbed `rg`/`grep` that records invocation, or by asserting findings parity).

- [ ] **AC-18: No-match never aborts under errexit/pipefail**
  - Given: a home dir where every content-gated registry file (`.npmrc`, `.docker/config.json`, kubeconfig, gradle.properties, shell rc, …) exists but contains **no** secret marker
  - When: `git-harden.sh --audit` runs (under the script's `set -euo pipefail`)
  - Then: the script completes normally (exit 0, no security findings); the routine scanner exit-1 on each file does not abort the run.

- [ ] **AC-19: Tier does not leak from a prior section**
  - Given: the inventory is reached with the ambient tier left at `security` by an earlier section, and the only inventory findings are `.env` files (hygiene) and a group-readable mode (hygiene)
  - When: the audit runs
  - Then: `TIER_SECURITY_ISSUES == 0` and `--audit` exits 0 — i.e. each finding set its own tier rather than inheriting `security`.

> Note: AC IDs are stable identifiers, not an ordering. Implementers should work the MoSCoW groupings (Must → Should → Could) top-to-bottom; AC-15 through AC-19 are all **Must Have** despite their numbers appearing after the Should/Could ACs below.

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
- The FR1.2 `scan_quiet` helper (new; `rg`-preferred, `grep` fallback). `rg` is an optional runtime accelerator, **not** a hard dependency — `grep` is always present.
- The global-gitignore management already in the script (for AC-12).

## Open Questions

> Should be empty before implementation.

- None outstanding. (Resolved with maintainer: 1Password-only; `chmod 600` is an applied action, default-Yes interactive and auto in `-y`; `.env` default depth 2 with `--scan-depth` override; minimal-read discipline FR1.1; scanner prefers ripgrep with grep fallback FR1.2, patterns constrained to the rg↔grep common regex subset.)
