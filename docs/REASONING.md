# Reasoning: Why Each Default Was Chosen

Every setting `git-harden.sh` audits or applies exists because of a specific attack vector or operational risk. This document explains the trade-off behind each one.

Settings are grouped the same way they appear in the script's audit output.

## Audit Tiers

Not every audited item carries the same weight, so each one belongs to one of three tiers:

- **security** — protects against a concrete attack vector (protocol restrictions, object integrity, hook control, credential storage, signing, …)
- **hygiene** — operational robustness and forensic readiness (reflog retention, `fetch.prune`, `user.useConfigOnly`, `pull.ff`, …)
- **preference** — ecosystem alignment with no security impact (`init.defaultBranch`, `log.showSignature`)

The audit summary reports issue counts per tier. In `--audit` mode, **only security-tier issues produce exit code 2** — hygiene and preference findings are reported but never fail a CI or fleet-compliance check. This keeps the exit code meaningful as a gate: a machine that fails the audit has an actual attack-surface problem, not a branch-naming opinion.

---

## Identity

### `user.useConfigOnly = true`

**What it does:** Prevents git from falling back to system-level identity (hostname, login name) when `user.name` and `user.email` aren't set in `.gitconfig`.

**Attack/risk mitigated:** Accidental commits as `root@localhost` or `builduser@ci-runner-7` that pollute history with unattributable authorship. Common on fresh VMs, containers, and CI environments.

**What could break:** Commits will fail if you haven't run `git config user.name` and `git config user.email`. This is intentional friction — the first commit on a new machine requires explicit identity setup.

**Why this default:** The cost of one extra setup step is negligible. The cost of unattributable commits in a regulated codebase is an audit finding.

---

## Object Integrity

### `transfer.fsckObjects = true` / `fetch.fsckObjects = true` / `receive.fsckObjects = true`

**What it does:** Forces git to validate the structural integrity and hash consistency of every object (blob, tree, commit, tag) during transfer, fetch, and receive operations. Malformed objects are rejected.

**Attack/risk mitigated:** Malicious or corrupted packfiles that exploit parsing vulnerabilities in the git binary. Historical CVEs include integer overflows in packfile handling and crafted objects that trigger code execution. Also catches silent data corruption from disk/network errors.

**What could break:** Adds ~5-10% overhead to clone and fetch operations on large repositories. More importantly: a meaningful number of popular, actively maintained repositories contain historic objects that are technically malformed but benign (zero-padded file modes, missing tagger lines, malformed committer dates) — cloning those will **fail**, not just warn. This is not a rare-edge-case setting.

**Mitigation when it bites:** Don't turn fsck back off globally. Downgrade the specific, known-benign message class instead, e.g.:

```
git config --global fetch.fsck.zeroPaddedFilemode ignore
git config --global fetch.fsck.badTimezone ignore
git config --global fetch.fsck.missingTaggerEntry ignore
```

This keeps structural/hash validation intact while tolerating the legacy quirk you actually hit.

**Why this default:** The performance cost is small and the failure mode is loud and fixable per message class. The alternative — silently accepting corrupted or malicious objects — has no upside.

### `transfer.bundleURI = false`

**What it does:** Disables the bundle URI mechanism, which allows git servers to redirect clients to pre-packaged bundle files for faster initial clones.

**Attack/risk mitigated:** Reduces attack surface. Bundle URIs could redirect clients to attacker-controlled servers serving malicious bundles. The feature is relatively new (Git 2.39+) and not widely audited.

**What could break:** Initial clone performance for repositories hosted behind CDN-backed bundle URIs. GitHub does not currently use this feature for public repositories.

**Why this default:** No measurable benefit for most users. The feature's security properties are still maturing.

### `fetch.prune = true`

**What it does:** Automatically removes local remote-tracking references (e.g., `origin/feature-x`) when the corresponding remote branch has been deleted.

**Attack/risk mitigated:** Stale remote refs can be confusing and misleading. In a security context, a deleted branch that still appears locally may cause a developer to base work on abandoned or reverted code.

**What could break:** Pruning only affects remote-tracking refs, not local branches. One caveat: when a remote-tracking ref was the *only* reference to some commits, pruning makes them unreachable and therefore eligible for garbage collection once the reflog entries expire. The extended reflog retention configured under Forensic Readiness keeps that window long (90+ days), but "zero downside" would overstate it.

**Why this default:** Hygiene with a negligible, reflog-mitigated downside. Tier: hygiene.

---

## Protocol Restrictions

### `protocol.version = 2`

**What it does:** Uses Git wire protocol v2 for client-server communication. Protocol v2 is more efficient (the server doesn't advertise all refs upfront) and has a smaller attack surface.

**Attack/risk mitigated:** Protocol v0/v1 sends the full ref advertisement on every connection, which leaks information about all branches and tags. Protocol v2 uses a capability-based negotiation that only transfers requested data.

**What could break:** Nothing in practice. Protocol v2 has been supported since Git 2.26 (April 2020) and all major hosting platforms support it. The client falls back gracefully if the server doesn't support v2.

**Why this default:** Strictly better. No known compatibility issues with any major git host.

### `protocol.allow = never` (default-deny)

### `protocol.https.allow = always` / `protocol.ssh.allow = always`

### `protocol.file.allow = user` / `protocol.git.allow = never` / `protocol.ext.allow = never`

**What it does:** Implements a default-deny protocol policy. Only HTTPS and SSH are permitted. The `file://` protocol is restricted to user-initiated operations. The unencrypted `git://` protocol and the `ext://` external transport helper are blocked entirely.

**Attack/risk mitigated:**
- `git://` transmits data unencrypted and unauthenticated — trivial MITM.
- `ext://` allows arbitrary command execution via transport helpers — this is by design, not a bug, but it's a dangerous capability that submodule URLs can exploit (e.g., CVE-2023-29007).
- `file://` is restricted because embedded bare repositories in cloned repos can be used for attacks (CVE-2022-39253).

**What could break:** Repositories that use `git://` URLs for remotes (rare — GitHub deprecated `git://` in 2022). The `url.https://.insteadOf` rewrite handles this automatically for HTTP URLs.

**Why this default:** The blocked protocols have no legitimate use case that can't be served by HTTPS or SSH. The risk/benefit ratio is extreme.

---

## Filesystem Protection

### `core.protectNTFS = true` / `core.protectHFS = true`

**What it does:** Blocks path manipulation attacks that exploit NTFS 8.3 short-name aliases (e.g., `GIT~1` resolving to `.git`) and HFS+ Unicode normalization (e.g., `.git` composed differently). Enabled on all platforms, not just Windows/macOS.

**Attack/risk mitigated:** CVE-2019-1352 (NTFS), various HFS+ attacks. A malicious repository can craft filenames that resolve to `.git/hooks/` on case-insensitive or normalizing filesystems, achieving code execution on clone.

**What could break:** Repositories containing filenames that happen to collide with NTFS 8.3 short names (extremely rare outside deliberate attacks).

**Why this default:** Enabled even on Linux because developers may clone repos onto external drives or share via mixed-OS teams.

### `core.fsmonitor = false`

**What it does:** Disables the filesystem monitor integration (fsmonitor, Watchman). This feature speeds up `git status` in large repos by using OS-level file change notifications.

**Attack/risk mitigated:** `core.fsmonitor` can point at an arbitrary command, which git then executes. **An important precision about what this setting does and does not protect against:** git config precedence means a *local* (`.git/config`) value overrides the global one — so setting `false` globally does **not** neutralize a repository that carries its own fsmonitor setting. What actually limits that attack is that `.git/config` is not transferred on clone; the realistic delivery vector is an embedded/planted `.git` directory, which is what `safe.bareRepository` and git's ownership checks (CVE-2022-24765 fix) address. The global `false` here is defense-in-depth: it prevents the feature from being silently enabled by tooling or copied configs, and it removes a code-execution-capable knob from the default environment.

**What could break:** Performance of `git status` in very large repositories (100k+ files) where fsmonitor provides significant speedups. Developers working on such repos can override this per-repo.

**Why this default:** Most repositories are not large enough to notice the difference. The attack surface is not worth the performance gain for typical use — but be aware it is a hardening layer, not the primary defense.

### `core.symlinks = false` (interactive-only, skipped in `-y` mode)

**What it does:** Tells git to not create symbolic links in the working tree. Instead, symlinks are stored as plain text files containing the link target path.

**Attack/risk mitigated:** CVE-2024-32002 — repositories with crafted submodules could trick git into writing files outside the repository via symlink following during clone, achieving remote code execution on Windows and macOS.

**What could break:** Any project that relies on symlinks: Node.js monorepos (`node_modules/.bin/`), shared configuration files, many build systems. This is the most likely setting to cause real workflow breakage.

**Why this default:** **Not applied in `-y` mode** specifically because of breakage risk. In interactive mode, the user is asked with a clear warning. We already mitigate the primary CVE via `submodule.recurse = false`, so this is defense-in-depth, not the only protection.

---

## Hook Control

### `core.hooksPath = ~/.config/git/hooks`

**What it does:** Redirects git hook execution from each repository's `.git/hooks/` directory to a centralized, user-controlled directory.

**Attack/risk mitigated:** Malicious repositories can include hooks (e.g., `pre-commit`, `post-checkout`) that execute on clone, commit, or checkout. By redirecting to a user-managed directory, repo-local hooks are ignored unless explicitly dispatched.

**How repo-local hooks keep working:** Redirecting hooks would otherwise *silently* disable every repo-local hook of every type — including security hooks teams installed deliberately (husky, lefthook, the `pre-commit` framework). To prevent that, the script installs **dispatch stubs** for all client-side hook types in the global hooks directory. Each stub forwards to the repository's own `.git/hooks/<name>` when present and executable. The `pre-commit` stub additionally runs the gitleaks secret scan first. The result: you get centralized control plus a visible choke point, without breaking per-repo workflows. (Repos that set `core.hooksPath` in their local config — husky v9 does — override the global value entirely and are unaffected.)

**What could break:** Hooks installed into `.git/hooks/` still run, but now *after* the global stub's own logic (for `pre-commit`: after the secret scan). Tools that verify their hook is "installed" by checking the effective `core.hooksPath` may complain.

**Why this default:** The attack is trivial to execute and devastating (arbitrary code execution). With dispatch stubs the usual breakage objection no longer applies.

---

## Pre-commit Hook (gitleaks)

### Gitleaks pre-commit hook installation

**What it does:** Installs a pre-commit hook at `~/.config/git/hooks/pre-commit` that runs `gitleaks protect --staged` before every commit, scanning the staged diff for secrets (API keys, passwords, private keys, etc.).

**Attack/risk mitigated:** Secret leakage — the single most exploited vulnerability class in git. GitGuardian's 2026 report found 29 million new secrets on public GitHub in 2025. Median time-to-discovery by attackers: 20 seconds.

**What could break:** False positives on test fixtures or example credentials may require bypassing with `SKIP_GITLEAKS=1 git commit`. Adds ~1-2 seconds to each commit.

**Fail-open by design, but loudly:** If gitleaks is not installed, the hook does not block commits — but it prints a clearly visible "secret scan SKIPPED" warning on every commit instead of silently doing nothing. Failing *closed* (blocking all commits until gitleaks is installed) was considered and rejected: it punishes machines the user doesn't fully control and trains people to delete the hook. A loud warning preserves the signal without the lockout.

**Why this default:** Both research reports rank pre-commit secret scanning as the #1 workstation-level defense. The `SKIP_GITLEAKS` bypass avoids the need for `--no-verify` which skips ALL hooks. After scanning, the hook dispatches to the repository's own `pre-commit` hook (see Hook Control above).

---

## Repository Safety

### `safe.bareRepository = explicit`

**What it does:** Requires `--git-dir` to be explicitly specified when working with bare repositories. Prevents git from automatically detecting bare repositories in the current directory tree.

**Attack/risk mitigated:** An attacker who can write to a shared filesystem (e.g., `/tmp`, network drives) can plant a bare `.git` directory that git will auto-detect, allowing them to influence git operations of other users in that directory.

**What could break:** Scripts or workflows that `cd` into bare repositories without specifying `--git-dir`. Server-side hooks on self-hosted git servers may need adjustment.

**Why this default:** Bare repository auto-detection in untrusted directories is a documented attack vector. Most developers never interact with bare repos directly.

### `submodule.recurse = false`

**What it does:** Prevents git from automatically initializing and updating submodules during clone, checkout, and pull operations.

**Attack/risk mitigated:** CVE-2024-32002 (clone-time RCE via crafted submodules), CVE-2023-29007 (config injection via overlong submodule URLs), and the general risk of pulling untrusted code automatically. Submodules are the primary vector for filesystem-based git attacks.

**What could break:** Projects using submodules require manual `git submodule update --init`. This is a one-time setup cost per clone.

**Why this default:** Submodule auto-recursion is the enabler for multiple critical CVEs. Explicit initialization is a small price for eliminating an entire attack class.

### `safe.directory = *` detection and removal

**What it does:** Detects and offers to remove the `safe.directory = *` wildcard, which completely disables git's directory ownership safety check.

**Attack/risk mitigated:** CVE-2022-24765 — on shared systems, any user can plant a `.git` directory in a location another user will `cd` into, achieving arbitrary config injection and potentially code execution via hooks.

**What could break:** Removing the wildcard may surface ownership errors for repositories on network drives or external media. These should be added individually: `safe.directory = /path/to/specific/repo`.

**Why this default:** The wildcard is always wrong. It exists because people encounter the ownership error and google a quick fix without understanding what they're disabling.

---

## Pull/Merge Hardening

### `pull.ff = only` / `merge.ff = only`

**What it does:** Refuses non-fast-forward merges and pulls. If the remote branch has diverged, git will error instead of creating a merge commit or silently rebasing.

**Attack/risk mitigated:** Force-pushed branches (rewritten history) are surfaced as errors rather than silently merged. This makes history rewriting attacks visible — the developer must explicitly decide how to handle the divergence.

**What could break:** Workflows that routinely use merge commits will need to switch to `git pull --rebase` or `git merge --no-ff` explicitly. Some teams prefer merge commits for feature branch integration.

**Why this default:** Silent non-fast-forward merges hide potentially dangerous history rewrites. Making divergence explicit is strictly safer. Teams that want merge commits can override per-repo.

---

## Transport Security

### `url."https://".insteadOf = http://`

**What it does:** Automatically rewrites any `http://` remote URL to `https://`, ensuring all HTTP-based git operations use TLS encryption.

**Attack/risk mitigated:** Plaintext HTTP transmits credentials and code in the clear, enabling trivial MITM attacks on any network between the developer and the git server.

**What could break:** Repositories hosted on servers that genuinely only support HTTP (no TLS). This is increasingly rare and is itself a security concern.

**Why this default:** There is no legitimate reason to use unencrypted HTTP for git operations in 2026.

### `http.sslVerify = true`

**What it does:** Enforces TLS certificate verification for all HTTPS git operations. This is git's default, but the script audits it because `http.sslVerify = false` is a common "quick fix" that people forget to undo.

**Attack/risk mitigated:** Disabling SSL verification allows MITM attacks even over HTTPS — the attacker presents any certificate and git accepts it.

**Audit semantics:** Unset is **not** the same as overridden. The audit reports an unset `http.sslVerify` as OK (git's built-in default is `true`) and only flags an explicit insecure override. The apply phase still pins it to `true` when other changes are being made, as a guard against future overrides in lower-precedence scopes.

**What could break:** Self-signed certificates on internal git servers. The proper fix is to add the CA certificate to git's trust store (`http.sslCAInfo`), not to disable verification globally.

**Why this default:** Ensuring the default hasn't been overridden. This is a safety net, not a new restriction.

---

## Credential Storage

### Platform-specific credential helper (`osxkeychain` / `libsecret`)

**What it does:** Configures git to store credentials in the OS keychain (macOS Keychain, Linux libsecret/GNOME Keyring) instead of plaintext files.

**Attack/risk mitigated:** `git-credential-store` writes passwords to `~/.git-credentials` in plaintext. Modern infostealer malware specifically targets this file. OS keychains encrypt at rest and require authentication to access.

**What could break:** Nothing. Credential helpers are transparent to git operations. The only friction is initial keychain authentication on first use.

**Why this default:** Plaintext credential storage is the #1 workstation-level credential theft vector according to both research reports.

---

## Credential Hygiene (audit-only)

### Plaintext file detection (`~/.git-credentials`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`)

**What it does:** Warns if plaintext credential files exist on the filesystem. Does not modify or delete them.

**Attack/risk mitigated:** These files are primary targets for infostealer malware and are trivially readable by any process running as the user.

**What could break:** Nothing — audit only.

**Why audit-only:** Deleting credential files could lock the user out of services. The script warns and lets the user decide.

---

## Global Gitignore

### `core.excludesFile = ~/.config/git/ignore`

**What it does:** Creates a global gitignore with patterns for common secret files (`.env`, `*.pem`, `*.key`, `credentials.json`), Terraform state (`*.tfstate`), and OS/IDE artifacts.

**Attack/risk mitigated:** Accidental commits of secrets and credentials. No amount of scanning catches what was never tracked in the first place.

**What could break:** Nothing — `.gitignore` only affects untracked files. Files already tracked are unaffected. The `!.env.example` negation allows committing example env files.

**Why this default:** A global gitignore is the simplest possible defense against the most common category of git security incidents.

---

## Defaults

### `init.defaultBranch = main`

**What it does:** Sets the default branch name for new repositories to `main` instead of `master`.

**Attack/risk mitigated:** None directly. This is an industry standardization that reduces confusion and aligns with GitHub's default (changed in October 2020).

**What could break:** Scripts that hardcode `master`. These should be updated regardless.

**Why this default:** Consistency with the ecosystem. Every major git hosting platform now defaults to `main`.

---

## Forensic Readiness

### `gc.reflogExpire = 180.days` / `gc.reflogExpireUnreachable = 90.days`

**What it does:** Extends git's reflog retention from the defaults (90 days reachable / 30 days unreachable) to 180/90 days. The reflog records every HEAD movement — commits, checkouts, resets, rebases.

**Attack/risk mitigated:** In a post-compromise investigation, the reflog is the primary tool for reconstructing what happened. Extended retention gives incident responders more time to discover and investigate force-push attacks, unauthorized commits, and branch manipulation.

**What could break:** Slightly more disk usage from retained reflog entries. The impact is negligible — reflogs are small text records.

**Why this default:** The Claude research report specifically recommends this for forensic readiness. The disk cost is trivial compared to the investigative value.

---

## Visibility

### `log.showSignature = true`

**What it does:** Shows GPG/SSH signature verification status in `git log` output by default.

**Attack/risk mitigated:** Makes unsigned or invalid signatures visible in normal workflow. Without this, developers must remember to use `git log --show-signature` to check.

**What could break:** More than "slightly more verbose" — be honest about this one:

- **Anything that parses `git log` output breaks.** Scripts, release tooling, and integrations that read log output without `--no-show-signature` get signature blocks interleaved with the text they expect to parse.
- **Every log invocation pays a verification cost** (an `ssh-keygen`/`gpg` call per displayed commit), which is noticeable on large histories.
- **Without a matching allowed_signers entry, every entry shows "No principal matched"** noise — which is why the script now smoke-tests the signature round-trip at setup time.

Scripts you control should use `git log --no-show-signature` or `git -c log.showSignature=false`. Tier: preference — turn it off if it fights your tooling; verification on the hosting platform is unaffected.

**Why this default:** Signature verification is only useful if people see the results. Making it visible by default closes the gap between "we sign commits" and "we verify signatures."

---

## Signing Configuration

### `gpg.format = ssh`

**What it does:** Uses SSH keys (instead of GPG) for commit and tag signing.

**Attack/risk mitigated:** Same as GPG signing — proves key possession at commit time, preventing commit author impersonation (the PHP git server compromise of 2021 is the canonical example).

**Why SSH over GPG:** SSH keys are already managed by every developer. GPG requires a separate keyring, key server interaction, and has a notoriously steep learning curve. SSH signing (available since Git 2.34) provides equivalent cryptographic guarantees with dramatically less operational friction.

**Trade-off:** GPG has native support for key expiration and revocation. SSH signing on GitHub lacks automatic expiration — a compromised SSH key's signatures remain "Verified" even after the key is removed from the account. For high-security environments, GPG may be preferable despite the friction.

### `commit.gpgsign = true` / `tag.gpgsign = true` / `tag.forceSignAnnotated = true`

**What it does:** Automatically signs all commits and tags with the configured signing key.

**Attack/risk mitigated:** Without signing, anyone who can push to a repository can impersonate any other developer by setting `user.name` and `user.email` to their values. Signed commits prove the private key holder created the commit.

**What could break:** Commits will fail if no signing key is configured. The script only enables these settings when a key is available.

**Why this default:** Commit signing is an accountability control. In the PHP compromise, malicious commits were attributed to Rasmus Lerdorf and Nikita Popov — signing would have immediately flagged them as forgeries.

### `gpg.ssh.allowedSignersFile = ~/.config/git/allowed_signers`

**What it does:** Points git to a local file mapping email addresses to their authorized public keys, enabling local signature verification without a network round-trip.

**What could break:** Nothing — the file is additive. Without it, local verification simply doesn't work (signatures are only verified on the hosting platform).

**The "No principal matched" trap:** verification matches the *committer email* against the principals in this file. If a repo overrides `user.email` (work vs. personal identities) or the entry was written with a different address, `git log` shows "Good signature … No principal matched" on every commit. To catch this at setup time instead of in every future log, the script offers a signing smoke test after enabling signing: it signs a test message with the configured key and verifies it against allowed_signers with the recorded principal. Per-identity setups need one allowed_signers line per email (the same key can appear on multiple lines).

---

## SSH Configuration

**How the script reads and writes `~/.ssh/config`:** ssh resolves options with *first-obtained-wins* semantics, and a directive inside a `Host github.com` block does not apply globally. The audit therefore only counts directives in **global scope** (top-level lines or a `Host *` block) — a directive that exists only in host-specific blocks is reported as "no global default". When applying, the script replaces values in global scope only, and appends new directives in a `Host *` block at the **end** of the file, so existing host-specific settings always keep precedence. `Include`-d files are scanned for keys (one level deep) but their directives are not audited or modified; the audit prints a notice when Includes are present.

### `StrictHostKeyChecking = accept-new`

**What it does:** Automatically accepts host keys on first connection (TOFU — Trust On First Use) but rejects changed keys on subsequent connections.

**Trade-off:** `ask` (the default) prompts on every new host — most users blindly type "yes" without verifying the fingerprint, providing no real security benefit. `no` accepts anything, including MITM attacks. `accept-new` is the pragmatic middle ground: it stops the prompt fatigue while still detecting host key changes (the actual attack scenario).

### `HashKnownHosts = yes`

**What it does:** Stores host entries in `~/.ssh/known_hosts` as hashed values instead of plaintext hostnames.

**Attack/risk mitigated:** If the known_hosts file is exfiltrated, the attacker cannot enumerate which servers the developer connects to. Hashing makes the file useless for reconnaissance.

**What could break:** Manual inspection of `known_hosts` becomes impossible. `ssh-keygen -F hostname` still works for lookups.

### `IdentitiesOnly = yes`

**What it does:** Only offers SSH keys explicitly configured in `~/.ssh/config` (via `IdentityFile`) or specified on the command line. Without this, ssh-agent offers ALL loaded keys to every server.

**Attack/risk mitigated:** A malicious SSH server can enumerate which keys a client holds by observing which public keys are offered during authentication. With many keys loaded, this leaks information about which services the developer has access to.

**What could break:** Connections that rely on ssh-agent offering the right key automatically will need explicit `IdentityFile` entries in `~/.ssh/config`. This is good practice regardless.

### `AddKeysToAgent = yes`

**What it does:** Automatically adds keys to the SSH agent after first use, so the passphrase is only entered once per session.

**Why this default:** Reduces friction for passphrase-protected keys. Without this, developers either skip passphrases entirely (worse security) or get frustrated re-entering them (leads to workarounds).

### `PubkeyAcceptedAlgorithms = ssh-ed25519,sk-ssh-ed25519@openssh.com,...`

**What it does:** Restricts which public key algorithms the SSH client will offer and accept. Limited to ed25519, ed25519-sk (FIDO2), and ECDSA NIST P-256 variants (including sk).

**Attack/risk mitigated:** Prevents negotiation down to weak algorithms (DSA, RSA with SHA-1). Forces modern cryptography.

**What could break:** Connections to legacy servers that only support RSA. These servers should be upgraded; RSA-SHA1 is deprecated by OpenSSH since version 8.7.

**Guards the script applies before setting this:**

1. **Key inventory.** If the only available keys (on disk *or* loaded in the SSH agent) are RSA/DSA, applying this directive would lock the user out of every server those keys authenticate to. The script warns, requires an explicit default-No confirmation, and skips entirely in `-y` mode.
2. **OpenSSH version.** The option is spelled `PubkeyAcceptedAlgorithms` from OpenSSH 8.5 and `PubkeyAcceptedKeyTypes` before that — and an unknown option in `~/.ssh/config` makes *every* ssh invocation fail with "Bad configuration option". The script detects the client version and writes the correct spelling, or skips the directive when the client is too old or not OpenSSH.

**Why these algorithms:** Ed25519 is the recommended default (fast, small keys, no parameter pitfalls). ECDSA P-256 is included because some FIDO2 hardware keys only support it. RSA is excluded because accepting it creates a fallback path to weaker cryptography.

---

## SSH Key Hygiene (audit-only)

### Weak key detection (DSA, ECDSA, short RSA)

**What it does:** Scans `~/.ssh/*.pub` and keys referenced in `~/.ssh/config` for deprecated or weak key types.

**Why audit-only:** Key migration requires generating new keys, updating authorized_keys on all servers, and reconfiguring services. This is too impactful to automate.

---

## Agent-Backed Keys

The end state the agent path targets: **a machine can pass the full audit and have working signing + authentication with zero plaintext private keys on disk.** The private key lives inside a vault SSH agent (1Password, Bitwarden) or a forwarded upstream agent; the on-disk footprint is at most a public-key stub.

### Why vault agents beat on-disk keys

A plaintext `~/.ssh/id_ed25519` is a single file an attacker who gets *any* code execution as your user can read and exfiltrate. A passphrase helps only while the key is at rest — the moment `ssh-agent` (or a long-lived `ssh` process) holds the decrypted key, it is recoverable from process memory. A vault-backed agent changes the trust boundary:

- The private key never leaves the vault's process. `ssh-add -L` and a signing request return a *signature*, never the key. There is no decrypted-key-on-disk and no plaintext file to steal.
- Each use can require an explicit, per-operation approval (1Password's biometric/Touch ID prompt, Bitwarden's unlock). An infostealer that reads files finds nothing; an attacker who wants a signature has to defeat an interactive approval, not copy a file.
- Revocation and rotation happen in one place (the vault), not across scattered `~/.ssh` directories.

This is why the audit treats an **unencrypted** private key in `~/.ssh` as a security-tier finding while leaving an encrypted one un-flagged, and why the signing wizard offers the agent path before offering to generate a file-based key.

### Forwarded-agent threat model

`SSH_AUTH_SOCK` is a generic agent endpoint. When it is set *alongside* `SSH_CONNECTION`/`SSH_TTY`, you are almost certainly inside an SSH session with **agent forwarding** (`ForwardAgent yes`) — your local agent's socket is exposed on the remote host. The script detects this and labels the socket "forwarded" rather than assuming a local vault agent.

The risk is concrete: **root (or any process able to read the forwarded socket) on the remote host can use your agent to authenticate as you, anywhere, for the lifetime of the connection.** They cannot extract the key, but they can borrow it. The mitigations the docs steer toward:

- Forward an agent only to hosts you fully trust, and prefer `ForwardAgent` scoped to a specific `Host` block over a global default.
- Prefer per-use approval (a vault agent makes each forwarded signature an interactive prompt on *your* machine, so a silent remote abuse is visible).
- For build/CI containers, a vault agent on the host with a narrowly forwarded socket beats copying a key file into the image.

Because a forwarded session has no local key files, the audit must not make file-based assumptions there: key inventory comes from probing reachable agents read-only (`ssh-add -L`), never from requiring an `~/.ssh/id_*` file to exist.

### `key::` signing — a literal public key, no file

Git 2.34+ with `gpg.format=ssh` accepts a `user.signingkey` of the form `key::ssh-ed25519 AAAA… comment`: the **literal public key**, inline, with no file path. This is the natural fit for an agent-only machine — the signing key is identified by its public material (which the agent will sign for), and nothing private touches disk. The audit understands this form: it accepts a `key::` value, and verifies the same public blob is present in `allowed_signers` so local verification round-trips.

### The public-key-stub pattern for `IdentitiesOnly`

`IdentitiesOnly yes` (which the SSH hardening applies) tells ssh to offer **only** the keys named by `IdentityFile`, instead of throwing every agent key at the server. That is good hygiene — it stops ssh from leaking *which* keys you hold to every host — but it has a sharp edge for agent-only users: with no `IdentityFile` lines, `IdentitiesOnly yes` would offer *nothing* and lock you out.

The resolution is the **public-key stub**: write `~/.ssh/<name>.pub` (public material only — consistent with the zero-plaintext goal) and a matching `IdentityFile ~/.ssh/<name>` line. ssh reads the `.pub` to know *which* identity to request, then asks the agent to do the actual signing; the private half stays in the vault. So before applying `IdentitiesOnly yes` the script checks that either a global `IdentityFile` exists or on-disk stubs match the agent keys; if the user is agent-only with no stubs, it offers to write the stubs (or, if declined, skips the directive with a warning rather than applying a lockout). `IdentitiesOnly yes` is never applied in a state that would stop agent keys from being offered.

---

## Plaintext Secret Inventory

Beyond SSH keys, a developer machine accumulates long-lived plaintext credentials: `~/.aws/credentials`, cloud-CLI tokens, package-registry tokens, kubeconfigs, database passwords, and `.env` files. These are the highest-value, lowest-effort target for an attacker who gets any code execution as the user — no exploitation required, just a file read. The Secret Inventory generalizes the four files the script already audited (`~/.git-credentials`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`) into a comprehensive, fixed registry and attaches concrete 1Password migration steps so each finding is actionable rather than merely alarming.

### The five solution shapes (and why this one)

When deciding *what* the tool should do about a plaintext secret, five shapes were on the table:

- **Shape A — audit-only (report path + kind).** Names the exposure; changes nothing.
- **Shape B — audit + `chmod 600`.** Additionally tightens permissions so other local accounts can't read it.
- **Shape C — drive the vault CLI** (`op item create`, `op plugin init`) on the user's behalf to migrate the secret.
- **Shape D — delete/rename the plaintext** after migration.
- **Shape E — rewrite the consuming config** to read from the vault (`op inject`/`op run` templates).

The feature ships **A + B only**, and *prints* C/D/E as next steps. The reasoning:

- **Never read or print a value.** Output is path + kind. A tool whose job is to reduce secret exposure must not become a new exposure by echoing secrets into a terminal or a log. (See "minimal-read discipline" below.)
- **Driving the vault CLI (C) is out of scope.** It would require an authenticated `op` session, the `op` command surface drifts between versions, and a tool that creates vault items on your behalf is one bug away from putting the *wrong* thing in your vault. Printing the exact `op plugin init aws` / `op inject` command is the honest line: actionable, but the user stays in control.
- **Deleting the plaintext (D) is the user's call.** Deleting a credential file that a still-running tool depends on can break a working setup; the script never deletes credential files (consistent with the v0.6 rule that `-y` never deletes anything). The "delete the plaintext after migrating" step is printed for the user to perform.
- **`chmod 600` (B) is the one safe mutation.** It only ever *tightens* permissions on a regular file the user owns; it never loosens, never recurses, never touches directories. That makes it safe to apply by default (interactive default-Yes, auto under `-y`) — it is additive hardening, categorically different from deletion.

### Why audit-only + chmod-only

The dividing line is reversibility and blast radius. `chmod 600` is reversible and cannot lose data, so it is applied. Everything that could *lose* a secret (delete), *create* the wrong vault item (drive `op`), or *break a working config* (rewrite the consumer) is left to the user with an exact printed command. This keeps the tool's own failure modes bounded: the worst thing a bug here can do is over-tighten a file's permissions or print a finding for a file that isn't really a secret — never destroy a credential or leak one.

### Bounded-depth walk and the prune list

`.env` files don't live at fixed paths — they sit in project trees (`~/projects/<repo>/.env`). Finding them needs a walk, but an unbounded `$HOME` scan on a machine with millions of files (think `node_modules`) would be slow enough that users disable the section, and following symlinks could wander out of `$HOME` entirely.

So the walk is **bounded and explicit**:

- **`--scan-depth N` (default 2)** means: scan files whose parent directory is at most N directory hops below `$HOME`. Default 2 covers `~/projects/<repo>/.env`; deeper layouts opt in with a larger depth. The cap is *visible* — an `[INFO]` line names the depth and the skipped directories, honoring the "no silent caps" principle.
- **A fixed prune allowlist** (`node_modules`, `.git`, `vendor`, `.cache`, `.cargo`, `.rustup`, `.npm`, `Library`, `.Trash`, `.terraform`, `pkg`) is `-prune`d before the file-match branch. This is a fixed list, not a "skip any dot-dir" heuristic — the heuristic was rejected as both ambiguous and in conflict with discovering GCP service-account JSON, which can legitimately sit under a config dir.
- **A single `find` invocation**, NUL-delimited (`-print0` consumed by `read -r -d ''`) so filenames with spaces/tabs/newlines are safe, with symlinks never followed (`-type f`, no `-L`). The performance target — under 3 seconds on a 200k-file home dir dominated by pruned trees — is guaranteed by `maxdepth` + the prune list, not by opportunistically scanning fewer files.

### Minimal-read discipline and its honest floor

Scanning a file for a secret is itself a sensitive act, so every content detection is constrained to ascertain *presence* while holding as little of the secret as technically possible:

- **Match the key/marker, not the value.** A detection regex anchors on the credential's identifying key (`aws_secret_access_key`, `_authToken=`, `oauth_token:`) and matches **at most one byte** of the value — solely to prove it is non-empty (`_authToken=[^[:space:]]`, never `_authToken=.+`). No `.+`/`.*`/`{n,}`/capture groups are applied to the value region.
- **Presence, never validation.** The script does not check that a token "looks real" (length, charset, checksum) — that would require reading the whole value. Key + non-empty value is enough to warn.
- **Quiet match, discarded output.** All scanning goes through one helper (`scan_quiet`) in quiet/first-match mode (`rg -q --max-count=1`, or `grep -qEm1`); the matched text is never captured into a variable, never piped through `sed`/`awk`/`cut`, never printed. One function is the single enforcement point, so auditing it audits the whole feature's read discipline.

**The honest floor:** both `rg` and `grep` read input a line at a time, so the *line* containing a secret transiently exists inside the **scanner's** process buffer for the duration of one match — `-m1` stops at the first matching *line*, not the first byte. This is the minimum achievable with line-oriented tooling. The guarantee the feature makes is precisely scoped: **the bash process never captures, stores, or emits the value**, and no detection pattern deliberately consumes past the first value byte. It does *not* claim a bounded number of bytes is read from the file — claiming otherwise would be dishonest. (One registry entry, URL-embedded credentials in `pip.conf`, must span `:`…`@` across the password by necessity; it is the documented exception, still never captured or printed.)

There is also one ambient-state hazard worth recording: the audit-tier global is *sticky*. Because the inventory runs after other sections (which leave the tier at `security`), every finding sets its own tier immediately before emitting — a forgotten `set_tier hygiene` would silently push `.env`/gradle noise into the security count and fail `--audit`. Noisy detectors (`.env`, `gradle.properties`, the secret-shaped-assignment heuristic) live in **hygiene**/**info** and never gate the audit exit code, so `--audit` flags real exposure without drowning in false positives.

---

## Admin Recommendations (informational only)

These settings require server/org-level access and cannot be applied by a workstation tool:

- **Branch protection rules** — prevent direct pushes to main
- **Vigilant mode** — flag unsigned commits visibly on the hosting platform
- **Force-push restrictions** — prevent history rewriting on protected branches
- **Fine-grained, short-lived tokens** — reduce blast radius of token compromise
- **Signed commit requirements** — enforce signing at the server level
- **Separate signing keys per org** — prevent cross-platform identity correlation (OSINT)
