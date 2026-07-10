# Instance tests

The doctest tier (`test/guide/`) verifies the **laptop side** of the
EC2/1Password guide: what crosses the SSH wire, what lands in argv, what gets
cleaned up. It cannot verify what only a real NitroTPM box can — TPM sealing,
`LoadCredentialEncrypted` delivery, and the ramfs semantics of
`$CREDENTIALS_DIRECTORY`. This tier does.

Everything runs over **SSM Session Manager** — no inbound ports, no SSH keys —
exactly as the guide prescribes.

## Scripts

| Script | Role |
|---|---|
| `create-test-instance.sh` | Stands up (or tears down) a disposable NitroTPM instance. Copies a stock AL2023 AMI encrypted into your account, re-registers it with `--tpm-support v2.0`, launches it with an SSM instance profile + IMDSv2-required + an inline Deny on Parameter Store, and confirms TPM sealing with a **real seal+unseal round-trip**. |
| `remote-tests.sh` | Runs **on** the instance as root. The actual assertions. Never prints the canary value; reports shape only, like the doctest harness. |
| `run-instance-tests.sh` | Ships `remote-tests.sh` over SSM, runs it, streams the result back, and exits nonzero if any check failed. |

## Usage

```sh
AWS_PROFILE=<p> ./create-test-instance.sh --create  --region us-east-2
AWS_PROFILE=<p> ./run-instance-tests.sh             --region us-east-2
AWS_PROFILE=<p> ./create-test-instance.sh --destroy --region us-east-2
```

The instance is **billable** (t3.small + one encrypted snapshot + AMI). `--destroy`
requires typing `yes` and removes the instance, both AMIs, and the snapshot.

## What it checks (24)

- **Phase 2.2** — `has-tpm2` exits 0; `/dev/tpmrm0` present; swap off; the
  `coredump.conf` drop-in yields effective `Storage=none`.
- **Phase 4.1** — a `--with-key=tpm2` seal round-trips the exact piped bytes; the
  sealed file does not contain the plaintext; and the load-bearing claim
  ("nothing on disk contributes to decryption") is tested directly: with the
  on-disk key removed, the `tpm2` blob still opens while a `--with-key=host`
  control blob does not, and recovers once the key is restored.
- **Phase 4.2** — `LoadCredentialEncrypted=` delivers the decrypted credential;
  `$CREDENTIALS_DIRECTORY` is `ramfs`, mode 0700, unreadable by a non-root user,
  and torn down when the unit stops.
- **Phase 3** — `systemd-run --pipe` delivers stdin to the unit; `LimitCORE=0`
  and `MemorySwapMax=0` reach the unit (verified in the unit's own cgroup).
- **Phase 5** — IMDSv1 is refused (HTTP 401); IMDSv2 works; the instance role
  cannot read Parameter Store (the inline Deny is in effect).
- **Regression (finding B1)** — `LoadCredential=name:/dev/stdin` does **not**
  deliver a piped secret, because the path is opened by PID 1, not by your pipe.
  Tested without `systemd-run --pipe`, which would otherwise mask the bug.

## Findings this tier caught

- **`has-tpm2` is not a sufficient TPM-readiness check.** On a stock AL2023 image
  `systemd-creds has-tpm2` reports every component `+yes` and exits 0, systemd is
  built `+TPM2`, and `/dev/tpmrm0` exists — yet `systemd-creds encrypt
  --with-key=tpm2` fails with *"TPM2 support not installed"*. systemd `dlopen`s
  the `tpm2-tss` runtime libraries at seal time and the base AMI ships none.
  `dnf install -y tpm2-tss` fixes it. Both the guide (Phase 2.2) and
  `create-test-instance.sh` originally trusted `has-tpm2` and would have reported
  a working TPM that could not seal a single secret; both now install `tpm2-tss`
  and verify with a real seal.

## Safety

- `remote-tests.sh` moves `/var/lib/systemd/credential.secret` aside for the
  key-separation test and restores it on any exit via a `trap`; a failure there
  would only leave the host key at its backup path, which the next run restores.
- Assertion messages report byte/line counts only — never the sealed value.
