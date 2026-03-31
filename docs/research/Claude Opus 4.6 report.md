# Git Security Hardening: A Practitioner's Reference

**The single most impactful thing an organization can do to harden its git security posture is enable push-time secret scanning.** GitGuardian's 2026 State of Secrets Sprawl report found **29 million new hardcoded secrets** on public GitHub in 2025 alone — a 34% year-over-year increase — with 64% of secrets from 2022 still unrevoked. Secret exposure remains the highest-likelihood, highest-impact attack surface because it requires zero sophistication to exploit: attackers scan public commits in real time, with a median time-to-discovery of **20 seconds** (Meli et al., NDSS 2019). Combined with branch protection enforcement, commit signing, and least-privilege token management, organizations can eliminate the most common git-related breach vectors with moderate effort.

This report covers the full git attack surface — from developer workstations through hosted platforms to CI/CD integration points — with platform-specific guidance for GitHub, GitLab, and Azure DevOps. Each section includes a threat model, numbered hardening checklist, real-world incident motivation, and residual risk assessment.

---

## Executive summary: ten highest-impact hardening measures

Ranked by risk reduction per unit of implementation effort for a typical 10–50 developer organization:

1. **Enable push-time secret scanning** (GitHub Secret Protection or GitLab Ultimate push protection). Blocks the most frequently exploited vulnerability class before it enters the repository. ~1 hour to enable org-wide.
2. **Require pull request reviews on default and release branches** with dismissal of stale approvals. Prevents direct pushes of malicious or vulnerable code. ~30 minutes per repository, automatable via rulesets.
3. **Replace classic PATs with fine-grained, short-lived tokens** (GitHub fine-grained PATs, GitLab project tokens, or GitHub Apps). Eliminates the "keys to the kingdom" single-token failure mode that enabled the tj-actions and Trivy compromises. ~1 day for audit and migration.
4. **Enforce 2FA/MFA for all organization members.** Prevents account takeover — the root cause of the Gentoo GitHub compromise. ~1 hour to enable; budget 2 weeks for member compliance.
5. **Install a pre-commit hook stack** (gitleaks + framework) on all developer machines. Catches secrets before they enter git history, where removal is costly. ~2 hours via `core.hooksPath`.
6. **Pin GitHub Actions to full commit SHAs**, not version tags. Prevents supply-chain injection via mutable tags, as exploited in the tj-actions/changed-files and Trivy incidents. ~1 day for audit and update.
7. **Enable SSH commit signing with ed25519 keys.** Prevents commit author impersonation — the attack vector in the PHP git server compromise. ~1 hour per developer.
8. **Deploy a hardened `.gitconfig` template** org-wide (`fsckObjects`, `safe.bareRepository = explicit`, protocol restrictions). Blocks multiple client-side attack classes including CVE-2024-32002. ~30 minutes.
9. **Stream audit logs to a SIEM** (or at minimum, enable and review them weekly). Provides detection of privilege escalation, branch protection tampering, and anomalous clone activity. ~4 hours for initial setup.
10. **Restrict AI coding agent permissions** — enforce least-privilege tokens, prevent `--no-verify` bypasses, and require PR review for all AI-generated commits. Addresses the fastest-growing secret exposure vector (AI-assisted commits leak secrets at **2× the baseline rate**).

For organizations that can implement only five changes this quarter, start with items 1, 2, 3, 4, and 5.

---

## Table of contents

1. [Secret exposure](#1-secret-exposure)
2. [Authentication and access control](#2-authentication-and-access-control)
3. [Commit integrity](#3-commit-integrity)
4. [Branch protection and code review enforcement](#4-branch-protection-and-code-review-enforcement)
5. [Supply chain attacks via git](#5-supply-chain-attacks-via-git)
6. [Git hosting platform hardening](#6-git-hosting-platform-hardening)
7. [Developer workstation git security](#7-developer-workstation-git-security)
8. [Audit, monitoring, and incident response](#8-audit-monitoring-and-incident-response)
9. [Platform security feature comparison](#9-github-vs-gitlab-vs-azure-devops-security-feature-comparison)
10. [Appendix A: Minimal `.gitconfig` hardening template](#appendix-a-minimal-gitconfig-hardening-template)
11. [Appendix B: Pre-commit hook stack recommendation](#appendix-b-pre-commit-hook-stack-recommendation)

---

## 1. Secret exposure

### Threat model

**Who:** Any attacker scanning public repositories, or an insider with read access to private repos. **What:** Credentials, API keys, private keys, database connection strings committed to git history. **How:** Automated scanning of commits in real time (bots monitor the GitHub Events API), manual inspection after a breach, or scraping of repository history.

The scale of this problem is staggering. The landmark NDSS 2019 study by Meli et al. ("How Bad Can It Git?") found over **100,000 repositories** with leaked secrets, with a median of **1,793 unique new keys appearing per day** across public GitHub. Of these, **89% were genuinely sensitive** — not test keys. GitGuardian's 2026 report shows the problem is accelerating: **29 million new secrets** detected in 2025, and repositories using AI coding assistants exhibit a **6.4% secret leakage rate** versus a 1.5% baseline.

The Uber 2016 breach is the canonical cautionary tale: attackers found **hardcoded AWS access keys** in a private GitHub repository (accessed via credential-stuffed passwords on accounts without MFA). Those keys unlocked an S3 bucket containing 57 million user records. The result: a **$148 million FTC fine** and the criminal conviction of Uber's CISO for concealing the breach.

### Hardening checklist

**1. Enable push-time secret scanning on the hosting platform.** GitHub Secret Protection ($19/committer/month, now available on Team plans) blocks pushes containing detected secret patterns before they enter the repository. GitLab Ultimate provides equivalent push protection via server-side pre-receive hooks. Azure DevOps offers GitHub Advanced Security for Azure DevOps with similar capabilities. Push-time blocking is dramatically more effective than post-commit alerting — GitGuardian data shows **70% of secrets leaked in 2022 remained active** through 2025, indicating that alert-only approaches fail due to slow remediation.

**2. Deploy a pre-commit secret scanning tool** on all developer workstations (see Appendix B for detailed tool selection). This catches secrets before they reach the server, complementing platform-side scanning.

**3. Maintain comprehensive `.gitignore` patterns.** Every repository should exclude `.env`, `*.pem`, `*.key`, `*.p12`, `*.tfstate`, `credentials.json`, `service-account*.json`, `.npmrc`, `.pypirc`, and similar files. Use a global gitignore (`core.excludesfile`) for personal patterns plus repository-level `.gitignore` for project-specific ones.

**4. Understand and address the persistence problem.** Running `git rm secret.key && git commit` does **not** remove the secret from history. Git stores content as immutable blob objects; the original blob persists in packfiles and is cloned by every downstream user. **The primary remediation is always to rotate the secret immediately.** History rewriting is secondary cleanup. Use `git-filter-repo` (recommended by the Git project as the replacement for the deprecated `git filter-branch`) or BFG Repo-Cleaner. After rewriting, run `git reflog expire --expire=now --all && git gc --prune=now --aggressive`, force-push, and contact platform support to purge cached objects. Note that forks retain the pre-rewrite history, and all developers must delete and re-clone.

**5. Configure custom secret patterns** for organization-specific credential formats (internal API keys, database connection strings) beyond the default detection patterns provided by platforms.

### Residual risk

Push-time scanning catches only **known secret patterns**. Generic passwords, custom token formats, and secrets embedded in binary files evade pattern-based detection. The 2026 GitGuardian report notes that **58% of leaked credentials are "generic secrets"** that bypass standard detection. Defense-in-depth (pre-commit hooks + push protection + periodic full-history scans with TruffleHog's active verification) reduces but does not eliminate this residual risk. The operational cost is modest: pre-commit hooks add ~1–3 seconds to each commit, and occasional false positives require developer time to triage.

---

## 2. Authentication and access control

### Threat model

**Who:** External attackers via credential theft, phishing, or token leakage; insiders with excessive permissions. **What:** Unauthorized access to repositories, code modification, secret exfiltration. **How:** Compromised PATs, stolen SSH keys, OAuth token theft, or account takeover via password reuse.

The April 2022 Heroku/Travis CI OAuth token compromise demonstrated the blast radius of over-privileged tokens: stolen OAuth tokens from two integrators provided access to private repositories of dozens of organizations, including GitHub's own npm infrastructure. More recently, the March 2025 tj-actions/changed-files compromise (CVE-2025-30066) stemmed from a single compromised PAT belonging to a bot account — that one token affected **23,000+ downstream repositories**. The March 2026 Trivy supply-chain attack (CVE-2026-28353, CVSS 10.0) traced back to a single org-scoped PAT (`ORG_REPO_TOKEN`) used across 33 workflows; incomplete rotation after the first breach enabled a second, more devastating attack.

### Hardening checklist

**1. Use ed25519 SSH keys exclusively.** Ed25519 provides equivalent security to RSA-4096 with much smaller keys (68 vs. 544 characters), faster operations, and no parameter-selection pitfalls. Generate with `ssh-keygen -t ed25519 -C "user@company.com"`. GitHub blocks legacy RSA/SHA-1 signatures. For maximum security, use FIDO2 hardware-backed keys: `ssh-keygen -t ed25519-sk -O resident -O verify-required`.

**2. Replace classic PATs with fine-grained, scoped tokens.** GitHub classic PATs (`ghp_` prefix) with `repo` scope grant read/write access to **every repository the user can access** — a textbook violation of least privilege. GitHub fine-grained PATs (`github_pat_` prefix) scope to specific repositories with granular permissions and mandatory expiration. GitLab project/group access tokens provide similar scoping. Set maximum PAT lifetimes via org policy: 90 days for CI/CD, 30 days for one-off tasks.

**3. Prefer GitHub Apps over PATs for automation.** GitHub Apps generate **short-lived installation tokens** (1-hour expiry) with fine-grained, repository-scoped permissions — not tied to any human account. They survive employee departures without credential rotation and provide auditable "on behalf of" action trails. This is the single most effective control against the "over-privileged bot token" failure mode.

**4. Enforce SAML SSO and audit legacy credentials.** On GitHub Enterprise Cloud, PATs and SSH keys must be separately authorized for SSO after creation. Critical gap: on GitLab, project/group access tokens and deploy keys **bypass SSO enforcement entirely**. On Azure DevOps, PATs bypass device compliance and MFA requirements — only IP-fencing policies apply to non-interactive flows.

**5. Deploy SSH Certificate Authorities** (GitHub Enterprise Cloud). Certificates expire automatically (e.g., daily), eliminating key rotation as a manual process. CAs uploaded after March 2024 require certificate expiration dates.

**6. Implement IP allowlisting where feasible** (GitHub Enterprise Cloud, GitLab self-managed, Azure DevOps via Entra Conditional Access). Practical limitation: dynamic IPs for remote workers require VPN routing, and GitHub-hosted Actions runners have dynamic IPs — requiring self-hosted or larger runners with static IPs.

### Residual risk

SSO enforcement does not protect against all token types on all platforms. IP allowlisting is operationally expensive with distributed teams. Hardware security keys (FIDO2) provide the strongest authentication but introduce device-dependency risk. The operational cost of migrating from classic PATs to fine-grained PATs or GitHub Apps is moderate — budget 1–2 days for audit and migration per team.

---

## 3. Commit integrity

### Threat model

**Who:** Attackers with push access (via compromised credentials or server compromise) impersonating trusted developers. **What:** Forged commits attributed to maintainers, containing backdoors or malicious changes. **How:** Git allows arbitrary `user.name` and `user.email` configuration — without signing, anyone can commit as anyone.

The March 2021 PHP git server compromise is the definitive case study. Attackers pushed two commits to the official `php-src` repository on the self-hosted `git.php.net` server: one attributed to PHP creator Rasmus Lerdorf, another to core maintainer Nikita Popov. Both inserted a backdoor that would execute arbitrary PHP code via a specially crafted HTTP header. The commits had `Signed-off-by` trailers — but those are plain text, not cryptographic signatures. The PHP project subsequently migrated to GitHub and mandated 2FA.

### Hardening checklist

**1. Enable SSH commit signing org-wide** (recommended over GPG for simplicity). SSH signing, available since Git 2.34, uses keys developers already manage — no GPG keyring overhead. Configuration:

```
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Maintain an `allowed_signers` file for local verification: `git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers`.

**2. Enable GitHub Vigilant Mode** (Settings → SSH and GPG keys → "Flag unsigned commits as unverified"). Without this, unsigned commits show no badge at all — making unsigned and forged commits visually indistinguishable from legitimate ones.

**3. Require signed commits via branch protection** on all default and release branches. GitHub supports this in both classic branch protection and rulesets. GitLab supports it via push rules. **Azure DevOps has no native commit signing verification** — signed commits are accepted but not validated or badged. Third-party pipeline decorators exist but are not equivalent.

**4. Understand what signing does and does not guarantee.** Signing proves **key possession at commit time** — it defeats impersonation and detects tampering. It does **not** prove the legitimate key owner was at the keyboard (a compromised machine with access to `ssh-agent` can produce valid signatures), and it does not prevent intentional malicious commits by a valid signer. Signing is an accountability control, not an authorization control.

**5. Monitor the SHA-1 to SHA-256 transition.** Git has used hardened SHA-1 (the `sha1collisiondetection` library) since Git 2.13.0, which detects known collision attack patterns with negligible false positive rates (< 2⁻⁹⁰). The SHA-1 chosen-prefix collision cost has fallen to approximately **$45,000** (Leurent & Peyrin, USENIX Security 2020, "SHA-1 is a Shambles"), and continues to decline with GPU advances. Git 3.0 (targeted for late 2026) will default new repositories to SHA-256, but **GitHub does not yet support SHA-256 repositories**, creating an ecosystem blocker. Practical risk today: low for most organizations due to the hardened SHA-1, but plan for migration.

### Residual risk

GitHub's squash-and-merge and rebase-and-merge operations create new unsigned commits, breaking signing chains. Sigstore/Gitsign offers keyless signing via OIDC identity, eliminating key management entirely, but GitHub does not yet display "Verified" badges for Gitsign signatures. For signing release artifacts (tarballs, binaries), signify or minisign are lightweight alternatives to GPG.

---

## 4. Branch protection and code review enforcement

### Threat model

**Who:** Malicious insiders, compromised accounts, or external attackers with any write access. **What:** Direct pushes of malicious code to production branches bypassing review. **How:** Pushing directly to unprotected branches, self-approving PRs, exploiting bypass vectors in branch protection configuration.

### Hardening checklist

**1. Require pull requests with at minimum one approving review** on default and release branches across all repositories. Use GitHub rulesets (preferred over classic branch protection — they aggregate restrictively, apply across fork networks, and support org-wide governance) or GitLab protected branches with "Allowed to push: No one."

**2. Enable "Dismiss stale approvals when new commits are pushed"** on all platforms. Without this, a developer can get approval, then push additional malicious commits and merge without re-review.

**3. Enable "Require approval of the most recent reviewable push"** (GitHub) or equivalent. This prevents a reviewer from pushing commits to a PR branch and then approving their own additions — a documented bypass vector identified by Legit Security that GitHub considers "working as expected."

**4. Check "Do not allow bypassing the above settings"** (GitHub) or restrict unprotect permissions (GitLab). By default, GitHub repository admins can bypass all branch protections. This single checkbox is the difference between "branch protection exists" and "branch protection is enforced."

**5. Use CODEOWNERS for security-critical paths** (authentication modules, cryptography, CI/CD configurations, the CODEOWNERS file itself). Protect the CODEOWNERS file with a self-referencing entry: `/.github/CODEOWNERS @security-team`. Validate that all listed code owners are active members with write permissions — invalid or departed users cause CODEOWNERS enforcement to fail silently.

**6. Require status checks before merging** (CI tests, SAST scans, secret scanning). Block merge unless all checks pass and branches are up to date with the target.

**7. Restrict force-push and branch deletion** on protected branches (default on GitHub and GitLab for protected branches, but verify explicitly).

### The "rubber stamp" problem

Branch protection is only as strong as the review process behind it. Research by Edmundson et al. (2013) found that **none of 30 developers** reviewing a web application found all seven known vulnerabilities, and more experience did not correlate with better detection. A 2024 study of OpenSSL and PHP code reviews found that even when security concerns were raised, **18–20% went unfixed** due to disagreements. Code review becomes security theater when PRs are approved in under two minutes without comments, when reviewers lack security training, or when PR sizes exceed 400 lines.

Minimum viable security review: keep PRs under 400 lines, run automated SAST and secret scanning before human review, require conversation resolution before merge, and designate security-trained reviewers as CODEOWNERS for sensitive paths.

### Bypass vectors to monitor

Admin override (without "Do not allow bypassing"), GitHub Actions self-approval (a bot can use `GITHUB_TOKEN` to approve PRs — disable via org settings), PAT-based PR creation and approval (if a `repo`-scoped PAT exists in Actions secrets), and CODEOWNERS misconfiguration (invalid users, unprotected CODEOWNERS file, or the "Require review from Code Owners" toggle not enabled).

---

## 5. Supply chain attacks via git

### Threat model

**Who:** Nation-state actors (xz-utils pattern), opportunistic attackers (pwn requests), or automated bots. **What:** Injecting malicious code into software supply chains via git-hosted repositories, build systems, or CI/CD pipelines. **How:** Social engineering of maintainers, exploitation of CI workflow misconfigurations, fork-based object injection, or dependency confusion.

The **xz-utils backdoor** (CVE-2024-3094, CVSS 10.0) represents the most sophisticated git-related supply chain attack to date. An attacker using the identity "Jia Tan" spent **over two years** building trust in the xz-utils project through legitimate contributions, while sockpuppet accounts ("Jigar Kumar," "Dennis Ens") pressured the burned-out sole maintainer to grant commit access. The backdoor was injected via the build system (M4 macros in the release tarball, not visible in the git source), targeting SSH on Debian/Fedora x86_64 systems. Discovery was accidental: Microsoft engineer Andres Freund noticed SSH logins consuming 500ms instead of 100ms.

The **Codecov breach** (January–April 2021) demonstrated a different vector: attackers extracted a GCS credential from a Docker image layer, modified the Codecov bash uploader script to exfiltrate CI environment variables (including git credentials and tokens) from approximately **29,000 enterprise customers'** CI runners. A customer discovered the compromise by comparing the downloaded script's SHA-256 hash against the one on GitHub — they did not match.

### Hardening checklist

**1. Pin all GitHub Actions to full commit SHAs**, not version tags. Mutable tags are the primary attack vector in Actions supply-chain compromises: the tj-actions/changed-files attacker retroactively updated multiple version tags to reference malicious commits. Use `uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11` instead of `uses: actions/checkout@v4`.

**2. Set `GITHUB_TOKEN` permissions to read-only by default** at the organization level (Settings → Actions → General → Workflow permissions → Read repository contents and packages permissions). Grant write permissions explicitly per-workflow using the `permissions:` block.

**3. Never use `pull_request_target` with checkout of the PR head.** The `pull_request_target` trigger runs with full repository secrets and write tokens but can be tricked into executing attacker-controlled code from a fork PR. If `pull_request_target` is required, gate execution behind a maintainer-applied label (e.g., `safe-to-test`) and never check out `github.event.pull_request.head.sha`. The February 2026 "hackerbot-claw" campaign exploited exactly this misconfiguration to steal org-scoped PATs from the Trivy project.

**4. Restrict fork creation for sensitive repositories** and audit the fork network. GitHub forks share the underlying object store — data from deleted forks or private forks can remain accessible via commit SHA in the parent repository. This is documented behavior, not a bug. Run `trufflehog github-experimental --repo <URL> --object-discovery` to scan for cross-fork object reference (CFOR) exposures.

**5. Implement SLSA Level 2+ build provenance.** Use the `slsa-framework/slsa-github-generator` reusable workflow to generate signed provenance attestations for release artifacts. Verify with `slsa-verifier` or `gh attestation verify` in deployment pipelines. SLSA L3 (hardened, isolated builds) would have made the SolarWinds attack — where malware was injected at compile time by the SUNSPOT implant, not in the source repository — significantly harder.

**6. Run OpenSSF Scorecard** weekly on all repositories. The automated tool evaluates branch protection, dangerous workflow patterns (including `pull_request_target` misconfigurations), pinned dependencies, token permissions, and signed releases. Integrate via the `ossf/scorecard-action` GitHub Action.

**7. Review `.gitmodules` changes as high-risk in code review.** Submodule URL manipulation (including CVE-2023-29007, which allowed arbitrary git config injection via overlong submodule URLs) is an active attack vector. Prefer proper package managers over submodules where possible.

### Residual risk

The xz-utils pattern — years of social engineering culminating in build-system-only backdoors invisible in git source — is extremely difficult to defend against programmatically. Reproducible builds, multi-maintainer release signing, and comparing source against release tarballs are the best mitigations, but they require significant process maturity. The SLSA framework provides a graduated path toward build integrity.

---

## 6. Git hosting platform hardening

### Threat model

**Who:** External attackers targeting organization-wide misconfigurations; insiders exploiting overly permissive defaults. **What:** Mass data exfiltration, privilege escalation, or persistence via platform settings. **How:** Account takeover of admins (Gentoo pattern), exploitation of default-permissive organization settings, or abuse of integration permissions.

### Hardening checklist

**1. Enforce 2FA for all organization members.** Available on all GitHub tiers (Free, Team, Enterprise). The Gentoo GitHub compromise (June 2018) was enabled by a single admin account without 2FA — the attacker guessed the password using a predictable password scheme. Non-compliant members are removed (GitHub) or blocked (GitLab). Budget a 2-week compliance window.

**2. Set base member permissions to "No permission" or "Read"** rather than the default "Write." Grant additional permissions via teams.

**3. Restrict repository creation to organization owners** or specific teams. Prevent uncontrolled proliferation of repositories with inconsistent security settings.

**4. Disable forking of private repositories** unless specifically required. All forks of public repos are always public — this cannot be overridden.

**5. Set default repository visibility to "Private"** (or "Internal" on Enterprise) to prevent accidental public exposure.

**6. Enable audit log streaming to a SIEM** (see Section 8). GitHub Enterprise streams to Splunk, Datadog, Azure Sentinel, S3, and GCS. GitLab Ultimate streams to HTTP endpoints, S3, GCS, and Azure Event Hubs.

**7. Apply CIS Benchmarks** where available. The CIS GitHub Benchmark (v1.2.0) and CIS GitLab Benchmark (v1.0.1, with 125+ recommendations) provide audit-ready configuration checklists. GitLab provides an open-source CIS benchmark scanner CLI tool. No standalone CIS benchmark exists for Azure DevOps.

### Self-hosted versus cloud

Self-hosting (GitHub Enterprise Server, GitLab self-managed) provides network isolation and data sovereignty but **shifts the patching burden** to the organization. Recent GitLab self-managed CVEs underscore this risk: CVE-2025-25291/25292 (CVSS 8.8, SAML authentication bypass), CVE-2025-6948 (CVSS 8.7, CI/CD pipeline authorization bypass), and CVE-2025-0605 (2FA bypass via Git CLI). For organizations without dedicated security infrastructure teams — the typical Three Backticks Security client — **cloud-hosted platforms are usually more secure** because the vendor handles patching, and the latest security features ship immediately.

---

## 7. Developer workstation git security

### Threat model

**Who:** Attackers who can influence repository content (malicious hooks, crafted objects) or access developer machines. **What:** Code execution on developer machines via cloned repositories, credential theft from insecure storage. **How:** Malicious git hooks, crafted git objects exploiting parsing vulnerabilities, symlink attacks, or plaintext credential files.

**CVE-2024-32002** (Critical) demonstrated this risk: repositories with submodules could trick Git into executing a hook during clone, achieving remote code execution on Windows and macOS. The `git clone` command — seemingly safe — became an attack vector.

### Hardening checklist

**1. Use a secure credential helper.** Never use `git-credential-store` (stores credentials as plaintext in `~/.git-credentials`). Per-platform recommendations: **Windows:** Git Credential Manager (bundled with Git for Windows). **macOS:** `osxkeychain` or GCM. **Linux:** `libsecret` or GCM. For CI/CD, use environment variables or short-lived tokens.

**2. Deploy the hardened `.gitconfig` template** from Appendix A org-wide. Critical directives: `transfer.fsckObjects = true` (verifies integrity of all transferred objects, catching malformed or crafted objects), `safe.bareRepository = explicit` (prevents embedded bare repository attacks), `protocol.git.allow = never` (disables the unencrypted, unauthenticated `git://` protocol), and `core.hooksPath` pointing to a centralized, organization-managed hooks directory.

**3. Never set `safe.directory = *`.** This wildcard **completely disables** the ownership safety check introduced in Git 2.35.2 (CVE-2022-24765), allowing any user on a shared system to exploit a planted `.git` directory. Add specific trusted directories individually.

**4. Set `core.hooksPath` to a centralized, version-controlled hooks directory.** This overrides per-repository `.git/hooks/` directories, preventing execution of untrusted hooks from cloned repos. Distribute standardized hooks (pre-commit secret scanning, commit message validation) via this path.

**5. Enable path traversal protections**: `core.protectNTFS = true` and `core.protectHFS = true` even on Linux servers, to protect developers on mixed-OS teams from NTFS 8.3 short-name attacks (CVE-2019-1352) and HFS+ Unicode normalization attacks.

### AI coding agents require specific controls

AI coding agents are now a material attack surface. Claude Code alone accounts for **over 4% of all public GitHub commits** as of March 2026. GitGuardian reports AI-assisted commits leak secrets at **double the baseline rate** (~3.2% vs. ~1.5%). Key risks and mitigations:

- **Agents bypass pre-commit hooks.** Cursor and Cline are documented to append `--no-verify` to git commits. Mitigation: enforce secret scanning server-side (push protection), not just client-side hooks. Consider the `block-no-verify` package or Claude Code's `PreToolUse` hooks.
- **Agents with overprivileged tokens.** AI agents given broad PATs can be exploited via prompt injection in repository content (issues, README files, code comments, `.cursorrules` files). The IDEsaster research (December 2025) found **100% of tested AI coding tools** vulnerable to prompt injection, with CVE-2025-53773 (CVSS 9.6) affecting GitHub Copilot. Mitigation: scope agent tokens to read-only on specific repositories; use ephemeral, OAuth-scoped credentials.
- **Agents performing destructive operations.** Reports document Cursor running `git push --force-with-lease --no-verify` without permission. Mitigation: use Claude Code's auto mode (which blocks force-pushes via a classifier) or restrict agent git permissions to exclude force-push.
- **62% of AI-generated C programs contain vulnerabilities** (FormAI-v2 dataset, 2024). Treat all AI-generated code as untrusted — enforce the same review requirements as human-authored code.

---

## 8. Audit, monitoring, and incident response

### Threat model

**Who:** Any attacker who has gained access — detection depends on monitoring coverage. **What:** Detecting and responding to compromised accounts, unauthorized changes, and data exfiltration. **How:** Audit log analysis, anomaly detection, and git forensics.

### Hardening checklist

**1. Enable and stream audit logs.** GitHub Enterprise streams to Splunk, Datadog, Azure Sentinel, S3, and GCS. GitLab Ultimate streams structured JSON to HTTP endpoints, S3, GCS, and Azure Event Hubs. Azure DevOps streams to Log Analytics, Splunk, and Event Grid (90-day default retention; audit streaming must be explicitly enabled — it is off by default).

**2. Monitor these critical events**: branch protection rule changes (`protected_branch.destroy`), force-pushes to default branches, repository visibility changes to public, new deploy key creation, PAT creation followed by mass cloning (correlated detection), admin role self-assignment, webhook creation/modification, and SSO/2FA policy changes.

**3. Extend reflog retention for forensic readiness.** Default retention is 90 days (reachable commits) and 30 days (unreachable). Extend with:
```
git config --global gc.reflogExpire 180.days
git config --global gc.reflogExpireUnreachable 90.days
```

**4. Know the forensic toolkit for post-compromise investigation.** `git reflog --date=iso` shows every change to HEAD with timestamps. Force-push events appear as "forced-update" in `git reflog show origin/main`. `git fsck --unreachable --no-reflogs` finds truly orphaned commits that may contain evidence. **Disable garbage collection immediately** during an investigation: `git config gc.auto 0`.

**5. Integrate git events into existing SIEM detection rules.** Pre-built integrations exist for Microsoft Sentinel (sentinel4github), Datadog Cloud SIEM (native GitHub rules), Panther (Python detection-as-code), Elastic Security (git hook execution detection on Linux endpoints), and Google SecOps (YARA-L rules for GitHub audit logs).

### Residual risk

Audit logs capture platform events, not all git operations. A sophisticated attacker who clones a repository via an authorized token and exfiltrates code will appear as normal `git.clone` activity. Anomaly detection (e.g., mass cloning of multiple private repositories in a short window) is the primary detection mechanism for data exfiltration, but tuning thresholds to avoid alert fatigue requires operational investment.

---

## 9. GitHub vs GitLab vs Azure DevOps security feature comparison

| Security capability | GitHub | GitLab | Azure DevOps |
|---|---|---|---|
| **MFA enforcement** | Org/Enterprise (all tiers); blocks non-compliant members | Instance/Group (all tiers); grace period configurable | Via Entra Conditional Access (not native) |
| **SSO/SAML** | Enterprise Cloud only | All tiers (self-managed); group-level (SaaS) | Native via Entra ID |
| **Fine-grained tokens** | Fine-grained PATs + GitHub Apps | Project/Group tokens | Scoped PATs (no repo-level scoping) |
| **Branch protection** | Rulesets (org-wide) + classic rules | Protected branches + push rules (Premium+) | Branch policies with build validation |
| **Commit signing verification** | ✅ GPG + SSH + S/MIME badges | ✅ GPG + SSH badges | ❌ No native support |
| **Secret scanning** | 200+ types; push protection ($19/committer/mo) | Secret detection; push protection (Ultimate) | Via GHAzDO ($19/committer/mo) |
| **SAST (code scanning)** | CodeQL ($30/committer/mo) | Multiple engines (Ultimate, $99/user/mo) | CodeQL via GHAzDO ($30/committer/mo) |
| **DAST** | Third-party only | ✅ Native (Ultimate) | Third-party only |
| **Container scanning** | Third-party only | ✅ Native (Ultimate) | Third-party only |
| **Fuzz testing** | Third-party only | ✅ Web API fuzzing (Ultimate) | Third-party only |
| **Dependency scanning** | Dependabot (free for alerts) | Native (Ultimate) | Via GHAzDO |
| **Compliance frameworks** | Rulesets | ✅ Centralized frameworks (Ultimate) | Branch policies only |
| **Audit log streaming** | Enterprise only | Ultimate only | Log Analytics, Splunk, Event Grid |
| **IP allowlisting** | Enterprise Cloud | Self-managed (network level) | Entra Conditional Access |
| **CIS Benchmark** | ✅ v1.2.0 | ✅ v1.0.1 (with scanner tool) | ❌ None |
| **Self-hosted option** | Enterprise Server | Self-managed CE/EE | Azure DevOps Server |
| **Security pricing** | Base $21/user + GHAS $49/committer/mo | Ultimate $99/user/mo (all inclusive) | Free base + GHAzDO $49/committer/mo |

**Key takeaway for Three Backticks Security clients:** GitHub offers the most granular token management (fine-grained PATs, GitHub Apps) and the strongest commit signing ecosystem. GitLab Ultimate provides the broadest native scanner coverage (DAST, container scanning, fuzzing) at a simpler all-inclusive price point. Azure DevOps lags significantly in git-specific security — no commit signing verification, no native MFA enforcement, and limited audit capabilities compared to the other two platforms.

---

## Appendix A: Minimal `.gitconfig` hardening template

```ini
# ============================================================
# SECURITY-HARDENED ~/.gitconfig — Three Backticks Security
# Deploy org-wide via configuration management
# ============================================================

[user]
    name = Your Name
    email = your.email@company.com
    # Prevent commits without explicit identity
    useConfigOnly = true

[credential]
    # OS-native secure storage (never use 'store')
    # Windows: manager | macOS: osxkeychain | Linux: libsecret
    helper = osxkeychain

[core]
    # Centralized hooks — overrides per-repo .git/hooks/
    hooksPath = ~/.config/git/hooks
    # Path traversal protections (enable on ALL platforms)
    protectNTFS = true
    protectHFS = true
    # Disable symlinks to prevent symlink-based attacks
    symlinks = false

[transfer]
    # Verify integrity of ALL transferred objects
    fsckObjects = true
    # Disable bundle URI fetching
    bundleURI = false

[fetch]
    fsckObjects = true
    prune = true

[receive]
    fsckObjects = true

[protocol]
    version = 2

[protocol "file"]
    # Restrict local file protocol (CVE-2022-39253)
    allow = user

[protocol "git"]
    # DISABLE unencrypted, unauthenticated git:// protocol
    allow = never

[protocol "ext"]
    # Disable external transport helpers
    allow = never

[safe]
    # Require explicit --git-dir for bare repos
    bareRepository = explicit
    # NEVER add: directory = *

[commit]
    gpgsign = true

[tag]
    gpgsign = true

[gpg]
    # SSH signing (simpler than GPG)
    format = ssh

[gpg "ssh"]
    allowedSignersFile = ~/.config/git/allowed_signers

[push]
    default = current
    autoSetupRemote = true

[init]
    templateDir = ~/.config/git/template
    defaultBranch = main

[url "https://"]
    # Force HTTPS for any git:// URLs
    insteadOf = git://
```

---

## Appendix B: Pre-commit hook stack recommendation

### Recommended stack: gitleaks via the pre-commit framework

**Why gitleaks over alternatives:** Gitleaks (Go, MIT license, 160+ built-in detectors) is the best general-purpose pre-commit secret scanner for most organizations. It strikes the optimal balance: fast execution (Go binary, no runtime dependencies), low false-positive rate, extensible TOML configuration, and active maintenance. TruffleHog v3 is more comprehensive (800+ detectors, active API verification) but its AGPL license and heavier runtime make it better suited for CI pipeline scanning than developer-workstation pre-commit hooks. detect-secrets (Yelp) excels in legacy codebases with its baseline approach but requires Python. git-secrets (AWS Labs) is AWS-focused and showing reduced maintenance (272+ unresolved issues).

### Installation via pre-commit framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
```

```bash
# Install pre-commit framework
pip install pre-commit
# Install hooks in the repository
pre-commit install
# Run against all files (first-time scan)
pre-commit run --all-files
```

### Organization-wide deployment via `core.hooksPath`

For enforcement beyond individual repositories:

```bash
# Create centralized hooks directory
mkdir -p ~/.config/git/hooks

# Create pre-commit hook that runs gitleaks
cat > ~/.config/git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Org-wide pre-commit secret scanning
if command -v gitleaks &> /dev/null; then
    gitleaks protect --staged --redact --verbose
    if [ $? -ne 0 ]; then
        echo "❌ Secret detected. Commit blocked."
        echo "If false positive, use: SKIP=gitleaks git commit"
        exit 1
    fi
fi
EOF
chmod +x ~/.config/git/hooks/pre-commit

# Set globally
git config --global core.hooksPath ~/.config/git/hooks
```

### Complementary CI pipeline scanning

Add TruffleHog in CI for deeper scanning with active verification:

```yaml
# GitHub Actions
- name: TruffleHog scan
  uses: trufflesecurity/trufflehog@main
  with:
    extra_args: --only-verified --results=verified,unknown
```

### Tool selection matrix

| Criterion | gitleaks | TruffleHog v3 | detect-secrets | git-secrets |
|---|---|---|---|---|
| **Best role** | Pre-commit hook | CI pipeline scan | Legacy codebase onboarding | AWS-only environments |
| **Speed** | Fast (Go binary) | Moderate (verification adds latency) | Fast (diff-only) | Fast (bash/grep) |
| **False positive rate** | Low | Very low (verification) | Low (baseline filtering) | Moderate |
| **Maintenance status** | Active | Active | Active | Low maintenance |
| **License** | MIT | AGPL 3.0 | Apache 2.0 | Apache 2.0 |
| **Operational cost** | ~1–2s per commit | ~10–30s per scan | ~1s per commit | ~1s per commit |

The recommended stack for a Three Backticks Security client is: **gitleaks as pre-commit hook** (developer workstation) + **TruffleHog v3 in CI** (verified scanning) + **platform push protection** (server-side enforcement). This three-layer approach provides defense-in-depth against the most common and damaging class of git security vulnerabilities.

---

*Prepared by Three Backticks Security. This document reflects the state of git security tooling and platform features as of March 2026. Platform features, pricing, and tool versions should be verified against current vendor documentation before implementation.*