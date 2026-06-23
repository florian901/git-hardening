# Research: Surfacing Dev/CLI Plaintext Secrets and Migrating Them to 1Password / Bitwarden

Status: **research** (informs a future v0.8 spec; not yet a commitment)
Author: investigation for issue #54
Date: 2026-06-23
Related: [`docs/specs/2026-06-09-agent-backed-keys.md`](../specs/2026-06-09-agent-backed-keys.md) (v0.7, SSH-key half of the same goal)

## Scope decisions (locked with the maintainer before research)

1. **Breadth — dev/CLI credentials only.** Cloud CLIs, package registries, container/k8s configs, API tokens in dotfiles/`.env`, database client creds, plaintext SSH/GPG keys, `.netrc`. Explicitly **out**: macOS Keychain / Secret Service enumeration, browser password stores, mail/VPN/db GUI clients, shell-history leak scanning. Those belong to a different, more invasive tool — not `git-harden`.
2. **Behavior — detect + concrete next steps only.** Audit-only. For each finding the tool prints the exact steps to move the secret into 1Password/Bitwarden and what to delete afterward. It never drives `op`/`bw`/`bws` and never deletes a credential. (The one exception worth considering: offering to `chmod 600` a world/group-readable secret file — additive and safe. See Open Questions.)
3. **Deliverable — this standalone research doc.** Keeps the v0.7 agent-backed-keys spec focused; this feeds a separate v0.8 spec if we proceed.

This matches the existing `audit_credential_hygiene` philosophy (warn, never touch) and the spec's Phase 4 ("instructions only, never drive CLIs").

---

## 1. What the script already does

`audit_credential_hygiene` (git-harden.sh) already flags four files, audit-only:

- `~/.git-credentials` — plaintext git passwords
- `~/.netrc` — plaintext network credentials
- `~/.npmrc` — only when it contains `_authToken=`
- `~/.pypirc` — only when it contains a `password` field

This research is essentially: **how far can that section reasonably grow, and what concrete migration advice can we attach to each finding?** The answer is "quite far, with care" — there are ~25 well-known credential locations a developer machine accrues, in clear families.

---

## 2. The dev-machine plaintext-credential landscape

Organized by family. "Detect by" = how the tool would find it without reading secret values into output. "Nature" distinguishes *plaintext* (literally readable) from *obfuscated* (trivially recoverable by any process running as the user — base64, SQLite, XOR) — both are in-scope because both fall to an infostealer running as the user.

### 2a. Cloud provider CLIs

| Secret | Location | Nature | Detect by | Severity |
|---|---|---|---|---|
| AWS static access keys | `~/.aws/credentials` | plaintext | file exists + `aws_secret_access_key` present | **security** (long-lived) |
| AWS (SSO/role config) | `~/.aws/config` | usually safe (SSO) | `aws_secret_access_key` in file | hygiene |
| GCP application-default creds | `~/.config/gcloud/application_default_credentials.json` | plaintext (refresh token or SA key) | file exists | **security** |
| GCP credential store | `~/.config/gcloud/credentials.db`, `access_tokens.db` | SQLite (obfuscated) | file exists | hygiene |
| GCP service-account keys | anywhere; often `*.json` with `"type":"service_account"` | plaintext | content marker `"private_key"` + `"type": "service_account"` | **security** |
| Azure tokens | `~/.azure/msal_token_cache.json`, `accessTokens.json` (legacy) | plaintext/obfuscated | file exists | hygiene |
| DigitalOcean | `~/.config/doctl/config.yaml` | plaintext token | `access-token:` present | **security** |
| Heroku API token | `~/.netrc` (`machine api.heroku.com`) | plaintext | already covered by `.netrc` check | **security** |
| Terraform Cloud token | `~/.terraform.d/credentials.tfrc.json`, `~/.terraformrc` | plaintext | file exists / `credentials` block | **security** |

### 2b. Git hosting / VCS CLIs

| Secret | Location | Nature | Detect by | Severity |
|---|---|---|---|---|
| git credentials | `~/.git-credentials` | plaintext | **already audited** | security |
| GitHub CLI token | `~/.config/gh/hosts.yml` | plaintext `oauth_token:` | file exists + `oauth_token` | **security** |
| GitLab CLI token | `~/.config/glab-cli/config.yml` | plaintext `token:` | file exists | **security** |
| Gitea/tea | `~/.config/tea/config.yml` | plaintext | file exists | security |

### 2c. Package registries

| Secret | Location | Nature | Detect by | Severity |
|---|---|---|---|---|
| npm token | `~/.npmrc` | plaintext `_authToken` (or base64 `_password`) | **already audited** | security |
| Yarn (berry) | `~/.yarnrc.yml` | plaintext `npmAuthToken` | content marker | security |
| PyPI | `~/.pypirc` | plaintext `password`/token | **already audited** | security |
| pip index auth | `~/.config/pip/pip.conf` | plaintext in URL | `://.*:.*@` in `index-url` | security |
| RubyGems | `~/.gem/credentials` | plaintext `:rubygems_api_key:` | file exists | security |
| Cargo | `~/.cargo/credentials.toml` | plaintext `token` | file exists | security |
| Composer | `~/.config/composer/auth.json` | plaintext `github-oauth`/`http-basic` | file exists | security |
| Maven | `~/.m2/settings.xml` | plaintext `<password>` | content marker | security |
| Gradle | `~/.gradle/gradle.properties` | plaintext signing/publish creds | content markers (`*.password`, `signing.*`) | **high false-positive** → hygiene |
| NuGet | `~/.config/NuGet/NuGet.Config` | plaintext/obfuscated `ClearTextPassword`/`Password` | content marker | security |

### 2d. Containers / Kubernetes

| Secret | Location | Nature | Detect by | Severity |
|---|---|---|---|---|
| Docker registry auth | `~/.docker/config.json` | base64 (obfuscated) unless `credsStore` set | `"auths"` with `"auth":` and no `credsStore`/`credHelpers` | **security** |
| kubeconfig | `~/.kube/config` (+ `$KUBECONFIG`) | plaintext client keys / tokens | `client-key-data:` or `token:` present | **security** |

### 2e. Database clients

| Secret | Location | Nature | Detect by | Severity |
|---|---|---|---|---|
| PostgreSQL | `~/.pgpass` | plaintext `host:port:db:user:password` | file exists | **security** |
| MySQL | `~/.my.cnf` | plaintext `password=` | content marker | **security** |
| MySQL login-path | `~/.mylogin.cnf` | obfuscated (AES with hardcoded key — trivially reversible) | file exists | **security** |
| MongoDB | `~/.mongorc.js`, `~/.dbshell` | plaintext (sometimes) | content marker | hygiene |

### 2f. Generic env-shaped secrets

| Secret | Location | Nature | Detect by | Severity |
|---|---|---|---|---|
| `.env` files | `$HOME/.env`, project `./.env`, `.env.*` | plaintext | file exists + `KEY=value` with secret-ish keys | hygiene (noisy) |
| shell rc exports | `~/.zshrc`, `~/.bashrc`, `~/.profile`, `~/.zshenv`, `~/.bash_profile` | plaintext | `export .*(TOKEN\|SECRET\|KEY\|PASSWORD\|API)=` | **high false-positive** → hygiene |
| SSH private keys | `~/.ssh/id_*` (unencrypted) | plaintext | **covered by v0.7 spec §1c** | security |
| GPG private keys | `~/.gnupg/private-keys-v1.d/` | passphrase-encrypted (usually) | dir non-empty | info |

**Total: ~25 distinct locations across 6 families**, on top of the 4 already audited. The clear-cut "this file IS a credential" cases (AWS, gcloud ADC, `.pgpass`, gh/glab tokens, doctl, terraform, rubygems, cargo, composer) are high-confidence and low-false-positive. The content-pattern cases (gradle, shell rc, `.env`) are noisy and belong in a lower tier or behind a flag.

---

## 3. Detection design principles

1. **Never read secret values into output.** Detect by file existence and, where needed, a boolean content marker (grep `-q`). Report the *path* and the *kind*, never the value — same rule as the existing credential-hygiene section. (The v0.6.0 review flagged backups leaking tokens; the same discipline applies here.)
2. **Existence-based vs content-based confidence.** Files that exist only to hold credentials (`.aws/credentials`, `.pgpass`, `.git-credentials`, `gh/hosts.yml`) → flag on existence (security tier). Files that are config but *may* embed secrets (`gradle.properties`, shell rc, `.npmrc`) → content marker required, lower tier, because false positives erode trust.
3. **Permission check is a cheap, high-value signal.** Any of these world- or group-readable (`stat` mode & 077) is a finding regardless of contents, and `chmod 600` is a safe additive fix. This is the strongest candidate for an *applied* action (vs advisory).
4. **Obfuscated ≠ safe.** Docker base64, `.mylogin.cnf`, gcloud SQLite are recoverable by any process as the user — flag them, but as a distinct "trivially recoverable" sub-message, not "plaintext."
5. **Tier with the v0.6.0 scheme.** Clear-cut long-lived cloud/registry/db creds → `security`. Permission issues and obfuscated-but-present → `hygiene`. Encrypted-at-rest (GPG) → `info`. Only `security` gates `--audit` exit 2 — keeps the CI gate meaningful and avoids drowning it in `.env` noise.
6. **Scope the filesystem walk.** `$HOME` dotfiles are bounded and safe. Scanning for `.env` is the one unbounded case — limit to `$HOME/.env` plus the current working directory (depth 1), never a recursive `$HOME` walk (slow, privacy-sensitive, false-positive-heavy). Document the limit (per the v0.6.0 "no silent caps" principle).

---

## 4. Migration targets — the five solution shapes

From verified current docs (1Password developer docs at `1password.dev`; Bitwarden help at `bitwarden.com/help`, mid-2026). Every plaintext secret maps to one of five mechanisms:

### Shape A — Agent (SSH keys only)
Private key lives in the vault; an agent serves it; nothing on disk.
- **1Password:** Settings → Developer → Use the SSH Agent. Socket `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock` (macOS) / `~/.1password/agent.sock` (Linux).
- **Bitwarden:** desktop app ≥ 2025.1.2, Settings → Enable SSH agent. Socket varies by install: `~/.bitwarden-ssh-agent.sock` (dmg/Homebrew/Linux native), App Store/Snap/Flatpak paths differ — **the tool must detect which**.
- → This is exactly the v0.7 agent-backed-keys spec. Not re-litigated here.

### Shape B — Shell plugin (1Password only; biometric-gated, removes the file)
`op plugin init <cli>` wraps a CLI so creds come from the vault. ~80+ CLIs incl. **aws, gh, glab, terraform, vault, stripe, openai, vercel, circleci**. Adds `source ~/.config/op/plugins.sh` to the rc file; the bare CLI name aliases through `op plugin run`. **This is the cleanest "delete the plaintext file entirely" path** for the CLIs it supports.
- **Bitwarden has no equivalent.** This is the single biggest 1P-vs-BW asymmetry for an interactive workstation.

### Shape C — Config-file templating (render at runtime / on demand)
For tools that insist on reading a config file (kubeconfig, docker, npmrc, pypirc, netrc, pgpass, maven settings):
- **1Password:** keep a committed `*.tpl` with `op://vault/item/field` references; render with `op inject -i file.tpl -o file`, or avoid disk entirely with `op run --env-file`.
- **Bitwarden:** `bws secret get <id> | jq -r '.value' > "$tmp"` materialize-to-temp, or `bws run` for the env-var path. (Note: `bws secret get` has **no value-only flag** — must pipe through `jq -r '.value'`.)

### Shape D — Env-var injection (the `.env` replacement)
For generic API tokens and `.env` files:
- **1Password:** **Environments** (beta) — import a `.env`, inject with `op run --environment <ID> -- <cmd>`; or a `.env` of `op://` refs + `op run --env-file=./prod.env -- <cmd>`.
- **Bitwarden:** `bws run -- <cmd>` injects every secret the token can read (scope with `--project-id`); secret KEY becomes the env var name.

### Shape E — Non-interactive / CI backing
- **1Password:** service account, `export OP_SERVICE_ACCOUNT_TOKEN=...`, then any `op read`/`op run`/`op inject` works headless.
- **Bitwarden:** machine account + access token, `export BWS_ACCESS_TOKEN=...`, then `bws`.

**Strategic read for git-harden's audience (interactive developer workstation):** 1Password offers a materially smoother "make the plaintext file disappear" story (shell plugins + native SSH agent + Environments + secret refs). Bitwarden's strength is CI/machine secrets via Secrets Manager (`bws`); its workstation story leans on `bws run` env injection and a newer desktop SSH agent. The advisor should reflect this — for, say, AWS it should lead with `op plugin init aws` for 1P users but a `bws`/env pattern for BW users.

---

## 5. Per-credential migration playbook

Detect which managers are present first (`command -v op`, `command -v bw`, `command -v bws`) and tailor. `‡` = mechanism unverified for that specific CLI (idiomatic application of a verified primitive, not a copied per-tool doc command — flag as such in output).

| Credential | 1Password next step | Bitwarden next step |
|---|---|---|
| **AWS** `~/.aws/credentials` | `op plugin init aws` (Shape B) | store keys as secrets → `bws run -- aws …` (Shape D) |
| **GitHub CLI** `gh/hosts.yml` | `op plugin init gh` (Shape B) | `bw`/`bws` store token → `export GITHUB_TOKEN=$(bw get password 'gh token')` |
| **GitLab CLI** `glab-cli/config.yml` | `op plugin init glab` (Shape B) | as GitHub |
| **Terraform Cloud** `credentials.tfrc.json` | `op plugin init terraform` (Shape B) | `bws run` with `TF_TOKEN_app_terraform_io` |
| **GCP ADC / SA JSON** | `op inject`‡ the SA JSON at runtime; or `op read` → temp file + `GOOGLE_APPLICATION_CREDENTIALS` | `bws secret get … \| jq -r .value > "$f"` + `GOOGLE_APPLICATION_CREDENTIALS` |
| **kubeconfig** `~/.kube/config` | `op inject -i ~/.kube/config.tpl -o ~/.kube/config`‡ | materialize to temp + `KUBECONFIG` |
| **Docker** `~/.docker/config.json` | `op read … \| docker login --password-stdin`‡ (+ set a `credsStore`) | `bws secret get … \| jq -r .value \| docker login --password-stdin` |
| **npm** `~/.npmrc` | `op inject -i .npmrc.tpl -o ~/.npmrc`‡ (`//registry/:_authToken=op://…`) | `.npmrc` `_authToken=${NPM_TOKEN}` + `bws run -- npm publish` |
| **PyPI** `~/.pypirc` | `op inject -i .pypirc.tpl -o ~/.pypirc`‡ | `bws run -- twine upload` (`TWINE_USERNAME=__token__`) |
| **`.pgpass` / `.my.cnf`** | `op inject`‡ a temp file at runtime; or `op run` exporting `PGPASSWORD`/`MYSQL_PWD` | `bws run` exporting `PGPASSWORD`/`MYSQL_PWD` |
| **RubyGems / Cargo / Composer** | `op inject`‡ the credentials file from a `.tpl` | materialize-to-temp or `bws run` with the tool's token env var |
| **Generic `.env` / dotfile token** | Environments (beta) import, or `.env` of `op://` refs + `op run` (Shape D) | `bws run -- <cmd>` (Shape D) |
| **SSH private keys** | 1P SSH agent (Shape A) | Bitwarden SSH agent (Shape A) |

Common closing step for every file-based case: once the vault path works, **delete (or `.bak`) the plaintext file** — but per scope, the tool only *prints* this step; it never deletes (mirrors v0.6.0 reset-signing safety: interactive, default-No, never in `-y`).

---

## 6. What this means for git-harden — recommended shape

A future v0.8 spec, structured to mirror the agent-backed-keys spec's "detect → advise → (narrow) apply → docs" arc:

**Phase A — Plaintext Secret Inventory (audit-only, extends `audit_credential_hygiene`).**
- Add the high-confidence existence-based detections (§2a–2e clear-cut cases) at `security` tier.
- Add permission auditing (mode & 077) across all detected secret files at `hygiene` tier.
- Add the noisy content-pattern detections (gradle/shell-rc/`.env`) at `hygiene` tier, behind the bounded filesystem-walk rule (§3.6).
- Output discipline: path + kind only, never values (§3.1).

**Phase B — Migration advisor.**
- Detect installed managers (`op`/`bw`/`bws`) and active agents (reuse v0.7 `detect_ssh_agents`).
- For each finding, print the tailored next-step (§5), leading with the smoothest mechanism for the manager the user actually has. Mark `‡` items as "idiomatic, verify against your version."
- If no manager is installed: print install pointers + the generic principle, then stop (don't nag).

**Phase C — The one safe applied action: permission hardening.**
- Offer `chmod 600` on world/group-readable secret files. Additive, reversible, no data loss. Everything else stays advisory (per scope decision: no CLI driving, no deletion).

**Phase D — Docs.**
- REASONING.md "Plaintext Secret Inventory" section + the five solution shapes.
- README "Moving your secrets into a vault" walkthrough (1P and BW tracks).

This composes cleanly with v0.7: the SSH-key half (Shape A) is the agent-backed-keys spec; this doc is the everything-else half, reusing the same agent-detection and the same never-delete safety rules.

---

## 7. Risks, false positives, non-goals

- **False positives erode trust.** `gradle.properties`, shell rc exports, and `.env` are the danger zone — keep them in `hygiene`, content-gated, and clearly worded as "may contain." A noisy security-tier finding that's actually benign trains users to ignore the tool.
- **Don't encourage lockout.** Advisory only; the "delete the plaintext" step is always the user's explicit action, never automated. Same lesson as the v0.6.0 reset-signing fix.
- **Obfuscated detection must not over-claim.** Say "recoverable by any local process," not "plaintext," for Docker/`.mylogin.cnf`/gcloud SQLite.
- **CLI churn.** `op`/`bw`/`bws` syntax changes; the `‡` commands are idiomatic, not pinned. The advisor should phrase them as "starting point, confirm with `--help`," and we should re-verify at spec time.
- **Non-goals (reaffirmed):** OS keychain / browser store enumeration; driving `op`/`bw`/`bws`; secret rotation; recursive `$HOME` scanning; anything requiring vault auth sessions.

---

## 8. Open questions for the v0.8 spec

1. **`chmod 600` as an applied action — yes or advisory-only?** Recommendation: offer it (Phase C). It's the only safe, lossless mutation here and directly reduces risk. Counter-argument: keeps the section purely audit-only and simpler.
2. **`.env` scanning breadth.** Home only? Home + cwd depth-1 (recommended)? Configurable? Recursive is off the table.
3. **No-manager-installed behavior.** Print install hints + generic advice once, or stay silent to avoid nagging? Recommendation: print once, gated behind the inventory actually finding something.
4. **Tailoring depth.** Do we maintain a per-CLI lookup table (which have a 1P shell plugin, which env var each tool reads) — higher maintenance but much better advice — or print generic Shape C/D guidance? Recommendation: small curated table for the top ~10 CLIs, generic fallback for the rest.
5. **Encrypted-at-rest (GPG private keys, age keys).** Flag as `info` ("present, ensure passphrase-protected") or skip entirely? Leaning info.
6. **Interaction with `core.excludesFile`.** Several of these (`.env`, `*.pem`, credentials.json) are already in the global gitignore the script writes. Worth cross-referencing in output: "detected on disk *and* gitignored — good; detected and *not* gitignored — add it."

---

## Sources

1Password (verified late 2025 / 2026, host migrated to `www.1password.dev`):
- CLI item create / fields / secret references / `op run` / `op inject`: `1password.dev/cli/item-create/`, `/cli/secret-reference-syntax/`, `/cli/secrets-environment-variables/`, `/cli/secrets-config-files/`
- Shell plugins: `1password.dev/cli/shell-plugins/` (+ `/aws/`, `/github/`)
- SSH agent: `1password.dev/ssh/get-started/`, `developer.1password.com/docs/ssh/agent/`
- Environments (beta): `1password.dev/environments`
- Service accounts: `1password.dev/service-accounts/use-with-1password-cli/`

Bitwarden (verified mid-2026):
- `bw` CLI: `bitwarden.com/help/cli/`
- Secrets Manager + `bws`: `bitwarden.com/help/secrets-manager-cli/`, `/secrets-manager-overview/`, `/access-tokens/`
- SSH agent: `bitwarden.com/help/ssh-agent/`, `contributing.bitwarden.com/architecture/deep-dives/ssh/agent/`

Caveats carried from source verification: 1Password **Environments** is beta; `bws secret get` has **no value-only output** (pipe through `jq -r .value`); Bitwarden SSH-agent socket path **varies by install method**; the `~/.ssh/config` `IdentityAgent` directive for Bitwarden is official-adjacent (third-party-documented, standard OpenSSH); no 1Password **shell plugin** was verified for gcloud/kube/docker/npm/pypi (those use Shape C `op inject`/`op run`). The dev-credential-file inventory (§2) is compiled from domain knowledge and should be spot-verified per tool at spec time.
