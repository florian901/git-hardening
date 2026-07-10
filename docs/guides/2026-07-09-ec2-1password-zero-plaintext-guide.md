# Zero-Plaintext Secrets on EC2 with 1Password — Step-by-Step Guide

Goal: provision and operate EC2 instances from a laptop where
**all secrets live in 1Password**, **nothing plaintext ever rests on the instance**,
and **authorization stays anchored to the laptop** (biometric approval).

Two facts constrain every design below.

**The 1Password SSH agent does not implement OpenSSH 8.9+ destination-constrained
forwarding** (`session-bind@openssh.com` / `restrict-destination-v00@openssh.com`).
Its per-key biometric prompt is session-scoped and does not show the destination
host, so it rate-limits — but does not prevent — socket hijacking by root on the
instance. Time-boxing the forward is the real control.

**The AWS/IAM control plane is a parallel authorization anchor.** Anyone holding
your AWS identity — a cached session token, an exported credential, an over-broad
IAM principal, a CI role — can `ssm:StartSession` and push EIC keys onto the box
with **zero biometrics involved**. The laptop-anchor story is only as strong as
the gating of the AWS credential itself, which is why Phase 0.3 keeps no
long-lived AWS key on disk — via SSO's short-lived token, or via the 1Password
plugin for static keys — and why the instance role must stay minimal.

---

## Phase 0 — Laptop prerequisites

### 0.1 Install and unlock the 1Password desktop app + SSH agent

Enable the SSH agent in 1Password → Settings → Developer → *Use the SSH agent*.
Keys stay in the vault; the agent exposes only signing operations.

- Docs: [1Password SSH agent — get started](https://www.1password.dev/ssh/get-started/)
- Socket paths:
  `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock` (macOS),
  `~/.1password/agent.sock` (Linux)

### 0.2 Install the `op` CLI with biometric unlock

```sh doctest=syntax
brew install 1password-cli   # macOS; see docs for Linux/Windows
op vault list                # should trigger a Touch ID prompt, not a password
```

- Docs: [Get started with 1Password CLI](https://www.1password.dev/cli/get-started/)
- Docs: [app integration / biometric unlock](https://www.1password.dev/cli/app-integration/)

### 0.3 AWS credentials with no long-lived key on disk

The goal is that no long-lived AWS credential sits plaintext on the laptop. How
you get there depends on how your account issues credentials.

**If you use AWS IAM Identity Center (SSO)** — the common case for org accounts —
you are already there. There is no long-lived key: `aws sso login` mints a
short-lived, cached token.

```sh doctest=syntax
aws sso login --profile my-profile
aws sts get-caller-identity --profile my-profile
```

**Do not run `op plugin init aws` on an SSO account.** The 1Password shell plugin
only provisions *static access keys*; it does not support SSO
([shell-plugins#210](https://github.com/1Password/shell-plugins/issues/210)).
Worse, `op plugin init aws` writes `alias aws="op plugin run -- aws"` into
`~/.op/plugins.sh`, which your shell sources — and that alias then intercepts
`aws sso login` itself, so you cannot authenticate at all. If you hit this,
remove the `aws` line from `~/.op/plugins.sh`, or bypass it once with
`command aws sso login`.

**If you use static access keys**, store them in 1Password and let the plugin
inject them per-invocation:

```sh doctest=syntax
op plugin init aws
# afterwards `aws` is an alias (interactive shells only!) that resolves
# credentials from the vault per call
```

- Docs: [1Password Shell Plugins — AWS](https://www.1password.dev/cli/shell-plugins/aws/)

> **The alias only exists in interactive shells.** Scripts, `ProxyCommand`, cron,
> and anything spawned as `sh -c …` get the bare `aws` binary with no 1Password in
> the loop. For those, invoke the plugin explicitly: `op plugin run -- aws …`
> (see the wrapper in 1.2). This caveat does not apply to SSO, where the cached
> token is picked up from `~/.aws/sso` by any `aws` process.

### 0.4 Session Manager plugin for the AWS CLI

```sh doctest=syntax
brew install --cask session-manager-plugin
```

- Docs: [Install the Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)

### 0.5 Curate which keys the agent offers (avoid `MaxAuthTries` exhaustion)

With many vault keys, SSH offers them in arbitrary order and servers drop you after
six attempts. Pin key order/scope in `agent.toml`:

```toml doctest=toml
# ~/.config/1Password/ssh/agent.toml
[[ssh-keys]]
item = "EC2 provisioning key"
vault = "Infra"
```

- Docs: [SSH agent config file (agent.toml)](https://www.1password.dev/ssh/agent/config/)

---

## Phase 1 — Instance transport: no inbound port 22, no long-lived keys

Use **SSM Session Manager** as the SSH transport (instance in a private subnet,
outbound-only; IAM-authorized; CloudTrail-audited) and **EC2 Instance Connect**
for ephemeral login keys (pushed public key valid 60 seconds).

### 1.1 Attach the SSM instance profile

The instance needs the `AmazonSSMManagedInstanceCore` managed policy and the SSM
agent (preinstalled on Amazon Linux / Ubuntu AMIs).

- Docs: [SSM — enable SSH connections through Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-getting-started-enable-ssh-connections.html)

### 1.2 Route SSH over SSM in `~/.ssh/config`

**With SSO**, `ProxyCommand` can call `aws` directly: the cached token is read
from `~/.aws/sso` by any process, and it expires on its own. Use
`ProxyCommand aws ssm start-session …` and skip the wrapper below.

**With static keys**, `ProxyCommand` runs in a **non-interactive** shell, so the
0.3 alias does not apply there. Use a wrapper that invokes the shell plugin
explicitly, so that opening the transport itself requires laptop authorization:

```sh doctest=script
#!/usr/bin/env bash
# ~/bin/aws-op — 1Password-gated aws for non-interactive callers (ProxyCommand etc.)
set -o errexit
set -o nounset
set -o pipefail
exec op plugin run -- aws "$@"
```

```ssh-config doctest=sshconfig
# ~/.ssh/config
Host prov-*
  User ec2-user
  ProxyCommand ~/bin/aws-op ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'
  # macOS (quotes required — the path contains spaces):
  IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
  # Linux: IdentityAgent ~/.1password/agent.sock
  # Never leave a hijackable multiplexed socket behind:
  ControlMaster no
  ControlPersist no
  ExitOnForwardFailure yes
```

Invoke as `ssh prov-i-0abc123…`. On the static-key path, **verify the 1Password
prompt actually fires** on first connect — if it doesn't, the `aws` call found
ambient credentials somewhere and your biometric gate is being bypassed. On the
SSO path there is no per-call prompt; the gate is `aws sso login` and the
token's lifetime, so keep that lifetime short.

- Docs: [ssh_config(5) — ProxyCommand, ControlMaster, ExitOnForwardFailure](https://man.openbsd.org/ssh_config)
- Docs: [1Password — use the SSH agent with a specific host (IdentityAgent)](https://www.1password.dev/ssh/agent/compatibility/)

### 1.3 Ephemeral login keys via EC2 Instance Connect

Skip permanent `authorized_keys` entries entirely. The throwaway keypair lives in
a captured temp dir and is shredded on exit — never leave stray private keys in
`$TMPDIR`:

```sh doctest=run:eic
set -o errexit -o nounset -o pipefail
eic_dir="$(mktemp -d)"
trap 'rm -rf "${eic_dir}"' EXIT
ssh-keygen -t ed25519 -f "${eic_dir}/eic" -N '' -C 'eic-ephemeral'
aws ec2-instance-connect send-ssh-public-key \
  --instance-id i-0abc123 --instance-os-user ec2-user \
  --ssh-public-key "file://${eic_dir}/eic.pub"      # accepted for 60 seconds
ssh -i "${eic_dir}/eic" prov-i-0abc123
```

(Or keep one dedicated provisioning key in the 1Password vault and use the agent —
then no key file exists at all; the EIC route just avoids *any* standing
`authorized_keys`.)

- Docs: [Connect using EC2 Instance Connect](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-methods.html)
- Docs: [EC2 Instance Connect Endpoint (private instances)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-using-eice.html)

---

## Phase 2 — Prepare the instance for sealed credentials (NitroTPM)

Runtime secrets will be sealed to the instance's virtual TPM so ciphertext on EBS
is useless off-instance (snapshots included). NitroTPM is **not** on by default:
the AMI must be registered with UEFI boot + TPM 2.0. Graviton1/2, Xen, Mac, and
bare-metal instances are unsupported; most current Intel/AMD Nitro types (and newer
Graviton families) work — check the prerequisites page.

### 2.1 Register (or pick) a NitroTPM-enabled AMI

```sh doctest=syntax
aws ec2 register-image --name my-app --architecture x86_64 \
  --boot-mode uefi --tpm-support v2.0 \
  --root-device-name /dev/xvda \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={SnapshotId=snap-...}'
aws ec2 describe-images --image-ids ami-... \
  --query 'Images[0].[BootMode,TpmSupport]'   # expect: uefi, v2.0
```

- Docs: [NitroTPM prerequisites](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html)
- Docs: [Enable NitroTPM on an AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-support-on-ami.html)

### 2.2 Verify on the instance

`systemd-creds has-tpm2` is necessary but **not sufficient**. On a stock Amazon
Linux 2023 image it reports every component `+yes` (`+firmware +driver +system
+subsystem`) and exits 0, yet an actual `--with-key=tpm2` seal still fails with
*"TPM2 support not installed"* — systemd `dlopen`s the `tpm2-tss` runtime
libraries and the base AMI ships none. Install them, then verify the way that
actually proves the sealing path works: seal and unseal a throwaway credential.

```sh doctest=syntax
sudo dnf install -y tpm2-tss   # the libtss2 runtime systemd dlopens at seal time
systemd-creds has-tpm2         # necessary, not sufficient (expect: yes)
printf probe | sudo systemd-creds encrypt --name=probe --with-key=tpm2 - /tmp/probe.cred
sudo systemd-creds decrypt --name=probe /tmp/probe.cred -   # expect: probe
sudo rm -f /tmp/probe.cred
```

Verified on a real NitroTPM `t3.small` (AL2023, systemd 252): without `tpm2-tss`
the seal fails though `has-tpm2` passes; with it, the round-trip succeeds.

Also disable swap (or use encrypted swap) so decrypted memory can never page out:
`swapon --show` should be empty; systemd units below additionally set
`MemorySwapMax=0`. And disable coredump persistence — a crashing service would
otherwise dump its decrypted credentials to `/var/lib/systemd/coredump/` on disk:

```ini doctest=ini
# /etc/systemd/coredump.conf.d/no-storage.conf
[Coredump]
Storage=none
```

- Docs: [systemd-creds(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html)
- Docs: [coredump.conf(5)](https://www.freedesktop.org/software/systemd/man/latest/coredump.conf.html)

> **No NitroTPM available?** (Graviton1/2, Xen, Mac, bare-metal, or an AMI you
> can't re-register.) You keep every runtime protection and lose the at-rest
> guarantee against volume-level copies. See
> [Appendix A](#appendix-a--running-without-nitrotpm) before you accept that.

---

## Phase 3 — Interactive provisioning (decision point)

Pick per your threat model:

| | **Track A: time-boxed agent forwarding** | **Track B: no forwarding, local-resolve + push** |
|---|---|---|
| Concurrent root on the instance gets | Everything Track B exposes, **plus** your forwarded agent as a signing oracle for every key it holds | Only the secrets you pushed in this session |
| Friction | Low — normal `ssh -A` workflow | Moderate — every secret transfer is explicit |
| When to use | You trust the instance *during* the provisioning window | You want the smallest possible blast radius per session |

Neither track protects an already-delivered secret from root acting while it is
in memory: root reads any process's ramfs. The difference is what else the
attacker gets.

### Track A — Time-boxed 1Password agent forwarding

Private keys never leave the vault; only signatures cross. 1Password prompts on
first use of each key from the forwarded session — but the approval covers the whole
OS-user session and doesn't show the destination, so **keep the window short**.

1. Enable forwarding **only** for provisioning hosts (never `Host *`):

   ```ssh-config doctest=sshconfig
   # In addition to the Phase 1 block:
   Host prov-*
     ForwardAgent yes
   ```

   - Docs: [1Password SSH agent forwarding](https://www.1password.dev/ssh/agent/forwarding/)
     (note their own warning: approval authorizes every process of that OS user)

2. Do the provisioning work in one sitting; the proxy socket dies with the session.
   Never combine with `ControlPersist` (Phase 1 config already forbids it).

3. Streaming env secrets during the session — resolve **locally** with `op inject`
   (which emits *only* the templated keys, never your whole environment) and pipe
   over stdin into a transient system unit. Never `SetEnv`/`SendEnv` (values land
   in `/proc/<pid>/environ`) and never CLI arguments (they land in
   `/proc/<pid>/cmdline`, which is what `ps` shows):

   ```sh doctest=run:stream
   set -o errexit -o nounset -o pipefail
   # Capture first: in a plain `op | ssh` pipeline both sides start at once,
   # so ssh would run (with empty stdin) even when op fails. Capturing makes
   # a failed inject abort here, before ssh ever executes.
   envblock="$(op inject -i .env.tpl)"
   printf '%s\n' "${envblock}" | ssh prov-i-0abc123 \
     'sudo systemd-run --wait --pipe --collect \
        -p MemorySwapMax=0 -p LimitCORE=0 -p PrivateTmp=yes \
        /opt/app/provision.sh'
   unset envblock
   # provision.sh reads KEY=value lines from ITS OWN stdin —
   # nothing in env vars, argv, or on disk, on either side
   ```

   with a template like:

   ```sh doctest=envtpl
   # .env.tpl
   DB_PASSWORD=op://Prod/db/password
   API_KEY=op://Prod/api/credential
   ```

   Notes:
   - `systemd-run --pipe` connects the unit's stdin to the SSH channel; do **not**
     try `LoadCredential=…:/dev/stdin` — credential paths are resolved by the
     service manager, whose stdin is not your pipe, so the credential arrives
     empty.
   - Assumes passwordless, TTY-less `sudo` (default on Amazon Linux/Ubuntu cloud
     images); on hardened images `sudo` in a non-interactive pipe will fail — in
     that case the unit never starts and no secret is delivered (fail closed).

   - Docs: [op inject](https://www.1password.dev/cli/reference/commands/inject/)
   - Docs: [secret reference syntax](https://www.1password.dev/cli/secret-references/)
   - Docs: [systemd-run(1)](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html),
     [systemd credentials overview](https://systemd.io/CREDENTIALS/)

### Track B — No agent forwarding at all

Same as Track A step 3, but `ForwardAgent` stays off and login uses the ephemeral
EIC key from Phase 1.3. There is no remote socket to hijack; the only exposure is
the secrets you explicitly streamed, held in memory for the life of the unit.

---

## Phase 4 — Unattended runtime secrets: deliver once, seal to the TPM

Deliver each secret **once** over the SSH channel, seal it with `systemd-creds`
bound to NitroTPM, and let the service decrypt it into the non-swappable,
service-private `$CREDENTIALS_DIRECTORY` at start. Plaintext never touches
instance disk — the pipe goes straight into the encryptor.

### 4.1 Deliver + seal in one shot (from the laptop)

```sh doctest=run:seal
set -o errexit -o nounset -o pipefail
# Read first, so a failed op read aborts before ssh ever runs and an empty
# secret can never be sealed. printf is a shell builtin: the value never
# appears in any process's argv.
secret="$(op read 'op://Prod/db/password')"
printf '%s' "${secret}" | ssh prov-i-0abc123 \
  'sudo mkdir -p /etc/credstore.encrypted && \
   sudo systemd-creds encrypt --name=db-password --with-key=tpm2 \
     - /etc/credstore.encrypted/db-password.cred'
unset secret
```

`--with-key=tpm2` (not the default `host+tpm2`) keeps the sealing key entirely in
the TPM — nothing on disk contributes to decryption, so a copied EBS volume or
snapshot cannot be unsealed elsewhere.

The guarantee covers *off-instance* copies, and nothing more. Root on the live
instance can still run `systemd-creds decrypt` at will. `systemd-creds` binds to
**no PCRs by default**, so a tampered kernel booted on the same instance unseals
too; pass `--tpm2-pcrs=` to bind it. This is an at-rest defense, not a
root-on-live-box defense.

- Docs: [op read](https://www.1password.dev/cli/reference/commands/read/)
- Docs: [systemd-creds(1) — encrypt, --with-key=](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html)

### 4.2 Consume in the service unit

```ini doctest=unit
# /etc/systemd/system/myapp.service
[Service]
LoadCredentialEncrypted=db-password:/etc/credstore.encrypted/db-password.cred
# myapp reads $CREDENTIALS_DIRECTORY/db-password — a file, not an env var
ExecStart=/usr/bin/myapp
LimitCORE=0
MemorySwapMax=0
PrivateTmp=yes
ProtectSystem=strict
```

The decrypted credential exists only in ramfs, visible only to this service.
`LimitCORE=0` (plus the Phase 2.2 `Storage=none`) keeps a crash from dumping the
decrypted secret to disk. For whole `.env` files: render the composite locally
with [`op inject`](https://www.1password.dev/cli/reference/commands/inject/),
seal it as one credential, and have the app read the file — avoiding
`/proc/<pid>/environ` entirely.

- Docs: [systemd.exec(5) — LoadCredentialEncrypted=](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LoadCredentialEncrypted=)

### 4.3 Only if the instance must mint secrets on its own: sealed Service Account

This relaxes the laptop-anchor constraint — document that deliberately. A
1Password **Service Account** token is a standing credential that can read the
vault, so if you use one at all:

1. Create it scoped **read-only to a single app-specific vault**, with an expiry
   (`--expires-in`).
   - Docs: [1Password Service Accounts](https://www.1password.dev/service-accounts/)
   - Docs: [Service Account security](https://www.1password.dev/service-accounts/security/)
2. Deliver and seal it exactly like 4.1 (`--name=op-token`), never writing
   plaintext to disk.
3. Consume it via the credentials directory. Render fetched secrets to a
   service-private tmpfs file — not into the app's environment (which would undo
   4.2's `environ` avoidance):

   ```ini doctest=unit
   [Service]
   LoadCredentialEncrypted=op-token:/etc/credstore.encrypted/op-token.cred
   RuntimeDirectory=myapp
   RuntimeDirectoryMode=0700
   ExecStartPre=/bin/sh -c 'OP_SERVICE_ACCOUNT_TOKEN="$(cat "$CREDENTIALS_DIRECTORY/op-token")" \
     exec op inject -i /opt/app/app.conf.tpl -o /run/myapp/app.conf'
   ExecStart=/usr/bin/myapp --config /run/myapp/app.conf
   LimitCORE=0
   MemorySwapMax=0
   PrivateTmp=yes
   ProtectSystem=strict
   ```

   Accepted residual: `exec` replaces the shell with `op inject`, so for the
   duration of the render the token sits in the `op inject` process's
   environment (`/proc/<pid>/environ`) — visible to root, which already owns
   the box in that scenario. `/run/myapp` is tmpfs (RAM); Phase 2.2 disabled
   swap, so it never reaches disk.

Prefer skipping this entirely: re-run 4.1 from the laptop (or CI you control)
whenever a secret rotates.

---

## Phase 5 — Standing guardrails checklist

- [ ] `ForwardAgent` only under `Host prov-*`, never `Host *`; `ControlMaster no`,
      `ControlPersist no`, `ExitOnForwardFailure yes` on those hosts.
- [ ] Remote `sshd_config`: `StreamLocalBindUnlink yes` (clears stale forwarded
      sockets) — [sshd_config(5)](https://man.openbsd.org/sshd_config).
- [ ] No secrets in EC2 **user-data** (readable by any process via IMDS), AMIs,
      unencrypted EBS, shell history, `SetEnv`/`SendEnv` (`/proc/<pid>/environ`),
      or CLI arguments (`/proc/<pid>/cmdline` — what `ps` shows).
- [ ] IMDSv2 required (`--metadata-options HttpTokens=required`) —
      [Configure IMDS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html).
- [ ] **`AmazonSSMManagedInstanceCore` is not a minimal role.** Its first
      statement grants `ssm:GetParameter` and `ssm:GetParameters` on
      `"Resource": "*"`, so root-on-instance can read **every Parameter Store
      parameter in the account** — including SecureStrings encrypted with the
      default `aws/ssm` key, whose key policy grants `kms:Decrypt` to every
      principal in the account when the call arrives via SSM
      (`"Principal": "*"` + `kms:ViaService` condition; verified by reading the
      key policy — no separate IAM `kms:Decrypt` is needed). Only SecureStrings
      under a *customer-managed* KMS key, where the instance role lacks
      `kms:Decrypt`, are safe from this. Attach the managed policy *plus*
      an inline `Deny` on `ssm:GetParameter*` and `ssm:DescribeParameters`, or
      build a customer-managed policy from the `ssmmessages:*` / `ec2messages:*`
      / `ssm:UpdateInstanceInformation` subset — and test both Session Manager
      and `send-command` against whatever you trim to.
      Docs: [AmazonSSMManagedInstanceCore policy JSON](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonSSMManagedInstanceCore.html)
- [ ] Swap off or encrypted; `MemorySwapMax=0` **and** `LimitCORE=0` on
      secret-holding units; `coredump.conf` `Storage=none` (Phase 2.2).
- [ ] No long-lived AWS key on disk. With SSO that is automatic; keep the token
      lifetime short. With static keys, every non-interactive `aws` invocation
      goes through `op plugin run --` (the 0.3 alias does not reach
      scripts/`ProxyCommand`) — confirm the biometric prompt fires on the first
      `ssh prov-*` of a session.
- [ ] The AWS credential is the second trust anchor: no long-lived AWS keys on
      disk, tight IAM on `ssm:StartSession` / `ec2-instance-connect:SendSSHPublicKey`,
      CloudTrail alerts on their use from unexpected principals.
- [ ] Audit trail: SSM/EIC give CloudTrail with your IAM identity —
      [Logging Session Manager activity](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-logging.html);
      1Password Business logs key approvals (per-key, not per-destination).
      SSH-over-SSM tunnels are ciphertext to SSM session logging — but a plain
      logged *interactive* `aws ssm start-session` shell records keystrokes, so
      keep secret delivery on the SSH-tunneled path.
- [ ] Re-check the load-bearing gap periodically: if 1Password ships
      `session-bind`/destination-constraint support, Track A's residual risk
      shrinks dramatically — watch the
      [1Password SSH agent release notes](https://releases.1password.com/) and
      [OpenSSH agent-restrict design doc](https://www.openssh.com/agent-restrict.html).

## Known gaps (as of 2026-07)

- 1Password agent: no destination constraints, no per-operation approval, no FIDO2
  `-sk` keys, no SSH certificates. If you need per-op hardware presence, use a
  FIDO2 `-sk` key with `verify-required` *outside* 1Password.
- `op` CLI cannot run remotely against the desktop app (local code-signed IPC
  only); community proxies (`op-forward`) expose the whole vault to a compromised
  instance behind spoofable prompts — treat as disqualified.
- No "host key in RAM" mode in systemd-creds (systemd #23566): non-TPM instances
  can't get a purely volatile master key.
- **Out of scope here:** revocation of a leaked sealed blob (re-seal + rotate at
  the source), rotation cadence, and multi-developer setups (per-dev IAM
  principals, per-dev agent keys, shared vault structure) — design those
  explicitly before rolling this out to a team.

---

## Appendix A — Running without NitroTPM

Everything above works on a plain EC2 box except for the sealing key.

`systemd-creds encrypt --with-key=host` derives the sealing key from
`/var/lib/systemd/credential.secret` — **a file on the root volume**. Ciphertext
and key therefore travel together. Anyone who snapshots the volume, detaches it,
or restores a backup gets both halves and decrypts offline, at leisure, forever.
With `--with-key=tpm2` the key never leaves the Nitro security chip and cannot be
exported, so the same snapshot is inert.

| | `--with-key=tpm2` | `--with-key=host` |
|---|---|---|
| Snapshot, backup, or volume attached to **another** machine | Inert — the key is in this instance's TPM and cannot be exported | **Decryptable** — the key is a file on the volume |
| Tampered kernel booted on **this** instance | Unseals, unless you bind PCRs (`--tpm2-pcrs=`) | **Decryptable**, and no PCR binding is available |
| Root on the live instance | Decrypts freely | Decrypts freely |
| ramfs `$CREDENTIALS_DIRECTORY`, service-private perms | Same | Same |
| `MemorySwapMax=0`, `LimitCORE=0`, `Storage=none` | Same | Same |
| Laptop-anchored auth, agent time-boxing, IMDSv2, minimal role | Same | Same |

So: you **keep every runtime protection** and **lose the at-rest guarantee
against volume-level copies**. That is a downgrade in *kind*, not degree — a
hardware guarantee becomes an access-control guarantee. "Nobody can decrypt this
snapshot" becomes "only someone with the right IAM permissions and KMS grant can
decrypt this snapshot, and CloudTrail will show me when they do."

Neither mode resists a tampered kernel on the instance itself by default, since
`systemd-creds` binds to no PCRs unless told to. The difference is that `tpm2`
*can* be bound to PCRs and `host` cannot: its key is a file, and whatever boots
the volume can read it.

### A.1 Seal with the host key

```sh doctest=run:seal-host
set -o errexit -o nounset -o pipefail
secret="$(op read 'op://Prod/db/password')"
printf '%s' "${secret}" | ssh prov-i-0abc123 \
  'sudo mkdir -p /etc/credstore.encrypted && \
   sudo systemd-creds encrypt --name=db-password --with-key=host \
     - /etc/credstore.encrypted/db-password.cred'
unset secret
```

Consumption (Phase 4.2) is byte-for-byte identical — `LoadCredentialEncrypted=`
does not care which key sealed the blob.

### A.2 Compensating controls

Because the key is now a file, the blast radius is defined by who can copy that
file. Close every path below; a subset leaves the key reachable.

- **Encrypt the root volume**, and treat the KMS key as the real secret.
  Restrict `kms:Decrypt`/`kms:CreateGrant` on it to the instance role and your
  admin principal — nothing else.
  Docs: [EBS encryption](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html)
- **Restrict snapshot exfiltration in IAM**: deny `ec2:CreateSnapshot`,
  `ec2:CopySnapshot`, `ec2:ModifySnapshotAttribute`, and
  `ec2:ModifyImageAttribute` outside a break-glass role.
  `ec2:ModifySnapshotAttribute` is how a snapshot becomes public.
- **Never back up `/var/lib/systemd/credential.secret`** to anywhere the
  ciphertext also lives. A whole-volume snapshot copies both halves.
- **Swap off, coredumps off** (Phase 2.2) — unchanged from Phase 4, and now
  load-bearing, since a memory image is another route to the plaintext.
- **Alert on use**: CloudTrail on `CreateSnapshot`/`CopySnapshot` against this
  volume from any principal but the expected one.
  Docs: [CloudTrail for EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitor-with-cloudtrail.html)

Verify the two properties you are relying on:

```sh doctest=syntax
# swap must be empty, or a decrypted credential can page to disk
swapon --show
# the host key exists and is root-only; anyone who reads it owns every blob
sudo stat -c '%a %U' /var/lib/systemd/credential.secret   # expect: 600 root
```

### A.3 When not to do this at all

The decision rule is **rotation cost**, not sensitivity:

- **Cheap to rotate** (app DB passwords, per-service API keys you can cycle in a
  script): `--with-key=host` plus the controls above is a reasonable trade.
- **Expensive or impossible to rotate** (a signing key, a long-lived third-party
  credential, anything a partner must re-provision): do **not** leave it on the
  instance at all. Use Track B (Phase 3): stream it from the laptop per run and
  keep it in ramfs for the life of the process. Without a TPM, an unattended
  restart then requires a human.

Do not reach for a 1Password Service Account (Phase 4.3) as the workaround here.
Without a TPM its token is a standing, vault-reading credential sealed by a key
sitting next to it — strictly worse than the secret it was meant to protect.

---

## Appendix B — SecretSpec on the dev laptop

[SecretSpec](https://secretspec.dev/) (Cachix, for devenv.sh) is a **declaration
layer**, not a storage or delivery mechanism. It is worth adopting on the laptop
and worth keeping strictly off the instance.

### B.1 The problem it solves

Phase 3's template hardcodes three separate facts in one line:

    DB_PASSWORD=op://Prod/db/password
    #            ^backend ^vault ^item/field

That couples *what secret the app needs* to *where it happens to live*. A
teammate whose vault is named `Infra` must edit the template; CI must edit it
again to use a service account; nothing anywhere states which secrets the
project actually requires, so a missing one surfaces as a runtime error.

`secretspec.toml` lives in version control and declares only the *what*:

```toml doctest=toml
[project]
name = "myapp"
revision = "1.0"

[profiles.default.DB_PASSWORD]
description = "Postgres password for the app role"
required = true

[profiles.default.API_KEY]
description = "Upstream vendor API key"
required = true
```

The *where* moves to per-developer config (`secretspec config init`), so the
same declaration resolves against your 1Password vault, a teammate's differently
named vault, or a CI service account, with no edit to anything in git:

```sh doctest=syntax
secretspec config init          # pick provider: onepassword://my-account@Infra
secretspec check                # every required secret resolvable? exit 0/1
```

- Docs: [Providers](https://secretspec.dev/concepts/providers/) —
  `onepassword://[account@]vault` for the desktop-app biometric integration,
  `onepassword+token://` for a CI service account.

### B.2 What it changes, and what it does not

| | With SecretSpec |
|---|---|
| Who authorizes | Unchanged — the 1Password provider shells out to `op`, same biometric prompt |
| Private keys / SSH agent | Unchanged — SecretSpec has nothing to do with Phase 1–3's agent story |
| Zero-plaintext at rest on the instance | **Unchanged** — sealing is still `systemd-creds`; there is no systemd-credentials, tmpfs, or memory-only provider |
| Which secrets a project needs | **Declared, checked in, and verifiable** (`secretspec check`) |
| Swapping backend, vault, or environment | **Config change, not a code change** |
| Onboarding a teammate | `secretspec check` names exactly what's missing |

It buys **developer experience and portability, and no additional security.**
Adopting it moves none of the three goals at the top of this guide.

### B.3 The one hard rule: `get`, never `run`

`secretspec run -- cmd` injects every declared secret **as environment
variables**. Across the SSH boundary that is precisely the disqualified pattern
from Phase 3: values land in `/proc/<pid>/environ`, are root-readable, and are
captured in core dumps. Serializing them back out would mean an `env` dump —
the exact anti-pattern Phase 3 forbids.

`secretspec get NAME` prints the bare value to **stdout**, which is what lets it
feed the existing pipeline without ever touching the environment:

```sh doctest=run:secretspec
set -o errexit -o nounset -o pipefail
# Resolve locally, one value at a time, straight into a variable — never
# `secretspec run` (env injection) and never `env`. Capturing before the pipe
# means a failed resolve aborts BEFORE ssh opens a channel.
envblock=''
for key in DB_PASSWORD API_KEY; do
  value="$(secretspec get "${key}" --profile production)"
  envblock+="${key}=${value}"$'\n'
done
printf '%s' "${envblock}" | ssh prov-i-0abc123 \
  'sudo systemd-run --wait --pipe --collect \
     -p MemorySwapMax=0 -p LimitCORE=0 -p PrivateTmp=yes \
     /opt/app/provision.sh'
unset envblock value
```

For the Phase 4.1 sealing path, substitute `secretspec get` for `op read`; the
rest of the command — and its at-rest guarantee — is untouched.

### B.4 Two traps

- **The `dotenv` provider writes plaintext.** `secretspec init --from dotenv` and
  `--provider dotenv` read and write a plaintext `.env` on disk — exactly what
  `dev-harden.sh`'s secret inventory flags. Pin the provider in checked-in
  config, and never let `dotenv` reach a machine that holds real credentials.
- **Never install SecretSpec on the instance.** It resolves secrets into a
  process environment and `execve`s. Every reason Phase 4.2 hands the app a
  *file* in `$CREDENTIALS_DIRECTORY` applies verbatim.

### B.5 Why it fits this repo

SecretSpec is maintained by Cachix for devenv.sh and integrates natively:
enable it in `devenv.yaml`, then reference `config.secretspec.secrets` from
`devenv.nix`. If your toolchain already runs through devenv, the declaration
layer costs one file and removes the per-developer template edits that Phase 3
otherwise requires.

- Docs: [SecretSpec overview](https://secretspec.dev/concepts/overview/)
- Docs: [1Password provider](https://secretspec.dev/providers/onepassword/)
