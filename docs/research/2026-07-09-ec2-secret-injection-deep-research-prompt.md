# Deep-Research Prompt: Zero-plaintext secret injection into EC2 via 1Password

> Paste everything below the line into a deep-research tool.

---

## Research question

I am a developer who provisions and operates AWS EC2 instances from a laptop. All
secrets (SSH keys, provisioning credentials, application `.env` secrets, API tokens)
live in 1Password. I want to compare and rank concrete architectures for getting those
secrets **onto/into EC2 instances** under the following hard constraints, and I want a
recommendation I can implement.

## Hard constraints

1. **Zero plaintext secrets at rest on the EC2 instance.** Secrets may exist only in
   process memory (or kernel-backed ephemeral stores like tmpfs/memfd/systemd
   credentials, if the trade-offs are clearly analyzed). No secrets baked into AMIs,
   user-data, EBS volumes, swap, or shell history.
2. **Authorization is anchored on the developer's laptop**, ideally via the local
   1Password app (biometric/Watchtower-style per-use approval). The instance should
   not hold long-lived credentials that can mint more credentials.
3. **Private SSH keys never leave the laptop** (or a hardware/vault boundary on the
   laptop). Signing operations may be brokered, key material may not move.
4. **Socket/agent hijacking must be mitigated or prevented** — assume a compromised
   or root-level attacker on the EC2 instance and analyze what they can do with each
   architecture, especially with forwarded agent sockets.

## Specific architectures to research, compare, and threat-model

For each: how it works mechanically, setup steps, what touches disk where, what a
root attacker on the instance gains, operational friction, and maturity/maintenance
status as of mid-2026.

### A. SSH agent forwarding of the 1Password SSH agent
- `ForwardAgent yes` with the 1Password agent socket (`~/.1password/agent.sock` /
  the Group Containers socket on macOS).
- Does 1Password's per-use authorization prompt fire for *forwarded* signing
  requests, and does that meaningfully defeat hijacking, or just rate-limit it?
- OpenSSH ≥8.9 **destination-constrained agent forwarding** (`ssh-add -h`,
  `RestrictDestination`): does it work with the 1Password agent at all (1Password
  implements its own agent — check protocol extension support)? If not, can a
  constraint-enforcing proxy agent sit between (e.g. `ssh-agent` restricted keys,
  `ssh-agent-filter`, or a small socat/guard shim)?
- `ssh-add -c` confirmation semantics vs. 1Password's own approval model.

### B. Reverse-forwarding the op socket / "named pipes over the network"
- `RemoteForward /run/user/1000/op-agent.sock ~/.1password/agent.sock` and
  socat-based Unix-socket tunneling: is exposing the 1Password agent (or the `op`
  CLI's session) to the remote host over an SSH channel viable, and how does it
  differ security-wise from ForwardAgent (StreamLocalBindUnlink, socket file perms,
  who can connect)?
- Can the **`op` CLI itself** run remotely against a forwarded socket, or does it
  require the local desktop-app IPC (`OP_BIOMETRIC_UNLOCK_ENABLED` uses a separate
  named pipe / XPC on macOS)? Distinguish clearly between (1) the SSH *agent*
  socket, (2) the op CLI ⇄ desktop-app IPC channel, and (3) 1Password
  **SSH-agent forwarding vs. CLI session forwarding** — which of these can safely
  cross a network boundary?

### C. Qubes-style split architecture ("split-gpg/split-ssh for the cloud")
- The Qubes split-gpg/split-ssh model: a qrexec RPC where the key-holding domain
  prompts per operation and only signatures cross the boundary. What is the closest
  equivalent for laptop → EC2? Candidates to evaluate:
  - Plain agent forwarding *is* essentially split-ssh — analyze the delta (qrexec's
    prompt + no socket impersonation vs. SSH channel).
  - Brokered signing services: `ssh-tpm-agent`, Sigstore-style keyless, or a small
    gRPC/SSH-RPC signer daemon on the laptop with per-op approval.
  - Hardware anchors: FIDO2 `-sk` resident keys with `verify-required`, YubiKey
    touch policies — do these compose with 1Password?
- Is there any established open-source project implementing "remote split-ssh with
  per-operation local approval" that is production-credible?

### D. Push/pull secret injection for env + provisioning secrets
- **Pull with local authorization**: `ssh host 'app'` where the *laptop* runs
  `op run --env-file` / `op inject` and streams env over the SSH channel (stdin,
  `SendEnv`/`SetEnv`, or a one-shot systemd unit reading from stdin). Analyze
  exposure: `/proc/<pid>/environ`, ps, core dumps, systemd unit files.
- **systemd credentials** (`LoadCredential=`, `systemd-creds encrypt` sealed to
  TPM2 on Nitro instances — do EC2 Nitro instances expose NitroTPM, and which
  instance types?): can a secret be delivered once over SSH and sealed so only the
  target service can read it, never touching plaintext disk?
- **1Password Connect server / Service Accounts / `op` on the instance**: compare
  running a Connect host or using a service-account token on EC2 against the
  "authorization stays on the laptop" constraint — this token *is* a plaintext
  credential at rest; can it be confined (IMDSv2-gated retrieval, KMS-wrapped,
  memory-only via systemd credential)? When is this acceptable vs. disqualified?
- **AWS-native hybrid**: laptop uses 1Password → short-lived AWS credentials
  (1Password Shell Plugins for `aws`), then Secrets Manager / SSM Parameter Store +
  instance IAM role for runtime secrets. Analyze honestly: this moves trust to the
  instance role, violating constraint 2 — quantify what's lost and whether
  SSM `SessionManager` + `aws ssm start-session` port-forwarding beats plain SSH.
- **EC2 Instance Connect** (ephemeral 60-second pushed public keys) and **SSH
  certificates** (step-ca / an SSH CA whose signing key lives in 1Password):
  short-lived credentials as an alternative to long-lived authorized_keys.

### E. Socket-hijacking mitigations (cross-cutting)
For A–C specifically, produce a threat table: attacker = non-root user on instance,
root on instance, or someone with an EBS snapshot. Cover:
- Per-connection ephemeral socket paths, `StreamLocalBindUnlink yes`, socket
  directory permissions, `ExitOnForwardFailure`.
- Time-boxing: forward only during an active provisioning session, never in
  long-lived `ControlMaster` connections; `ControlPersist` risks.
- Per-use approval (1Password prompts, `ssh-add -c`) — what does the prompt
  actually display, and can an attacker's request be distinguished from mine?
- OpenSSH agent **destination constraints** in depth: which agents implement the
  `restrict-destination-v00@openssh.com` extension (OpenSSH ssh-agent, 1Password,
  Bitwarden, gpg-agent, ssh-tpm-agent)?
- Auditing: can I log every signing operation with requester identity?

## Deliverables

1. A **comparison matrix** (architecture × constraints 1–4 × friction × maturity).
2. A **threat model per architecture** (what root-on-instance gets, residual risks).
3. A **ranked recommendation**: one primary architecture for (a) interactive
   provisioning from the laptop and (b) unattended app runtime secrets, with the
   exact commands/config to implement each (ssh_config stanzas, systemd units,
   `op` invocations).
4. A short list of **disqualified approaches** with the specific constraint each
   violates (e.g. secrets in user-data, service-account token on disk, unrestricted
   ForwardAgent).
5. Open questions / gaps where tooling doesn't exist yet (e.g. if 1Password's agent
   lacks destination constraints, note the feature request / issue tracker status).

Prefer primary sources: OpenSSH release notes and PROTOCOL.agent, 1Password
developer docs (SSH agent, `op run/inject`, Connect, Service Accounts, agent.toml),
systemd-creds docs, AWS NitroTPM/SSM/Instance Connect docs, Qubes split-gpg/split-ssh
design docs. Cite versions and dates — agent-constraint support has changed across
OpenSSH 8.9–9.x and 1Password 8 releases.
