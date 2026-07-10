# Guide doctests

`doctest.sh` is an Elixir-doctest-style harness for
`docs/guides/2026-07-09-ec2-1password-zero-plaintext-guide.md`.

Run it:

```sh
test/guide/doctest.sh                    # default guide
test/guide/doctest.sh path/to/other.md   # any annotated markdown
```

## The coverage guarantee

Every fenced code block in the guide **must** carry a `doctest=<mode>`
annotation on its info string:

    ```sh doctest=run:seal

A block without an annotation is reported `FAIL … no doctest= annotation`. That
is the whole point: you cannot add an untested command to the guide.

Stated precisely, because the guarantee is only as good as the parser:

- **There is no opt-out mode.** Every block gets a checker.
- **Markdown the extractor cannot parse unambiguously is a `FATAL` error, never
  a silent skip** — blockquoted fences, tilde fences, tab-indented fences,
  closing fences with trailing text, and unterminated blocks all abort the run.
  A malformed closing fence used to swallow the *next* block, silently disabling
  its security assertions while the summary still read green. Invisibility is
  the failure mode this harness exists to prevent, so it must be impossible.
- **What `syntax` mode proves is narrow.** `bash -n` alone passes on an empty
  file, on arbitrary prose, and on `rm -rf /`, so that mode additionally
  requires the block to invoke a command the guide claims to use. It still only
  shows the snippet *parses* and names a real tool. The security-relevant
  checks are the `run:*` scenarios.

## Modes

| Mode | What it does |
|---|---|
| `syntax` | `bash -n`, plus the block must be non-empty and invoke a command the guide claims to use. Proves the snippet *parses* and names a real tool — **not** that it is correct. |
| `script` | `bash -n` + `shellcheck`. For complete scripts the reader saves to a file. |
| `sshconfig` | Rejects inline `#` comments (ssh_config has none — they become part of the value), then parses with the real `ssh -G -F`. |
| `toml` | Parsed with `python3 -m tomllib`. |
| `ini` | Static section/`key=value`/continuation validation; rejects inline comments in values. |
| `unit` | `ini` checks plus `systemd-analyze verify` where available (Linux). |
| `envtpl` | Every line is a well-formed `KEY=op://vault/item[/section]/field` reference. |
| `run:<name>` | `bash -n` + `shellcheck`, then **executes** the block against stub `op`/`secretspec`/`aws`/`ssh` binaries and runs security assertions. |

`syntax`/`script`/`toml`/`unit` degrade to `SKIP` when their checker is absent.
**`run:*` blocks never skip on a missing shellcheck** — the execution assertions
are the security-relevant part, so lint is advisory there and only a real lint
*failure* is fatal.

## Execution scenarios

Stubs live in `stubs/` and shadow the real binaries via `PATH`. They never touch
a vault, AWS, or the network. `op` honors `OP_STUB_FAIL=1` to simulate failure;
`ssh` records its argv and captures stdin for assertions.

- **`run:eic`** (Phase 1.3) — the `aws` stub fails unless the `file://` path
  exists and holds an ed25519 public key *at call time*, catching the
  `mktemp -d` → `/path/to/eic.pub` mismatch. Then asserts `ssh -i` used that
  same key and the `trap` removed the keypair, so no private key is left in
  `$TMPDIR`.
- **`run:stream`** (Phase 3, Track A step 3) — asserts stdin carries *exactly*
  the two templated keys (an `env` dump fails), the secret never appears in
  `ssh` argv, the remote command uses `systemd-run`, and that with
  `OP_STUB_FAIL=1` the block fails **and `ssh` never runs** (no empty-secret
  delivery).
- **`run:seal`** (Phase 4.1) / **`run:seal-host`** (Appendix A.1) — assert stdin
  carries exactly the bare secret, the secret never reaches argv, the remote
  command seals via `systemd-creds encrypt` **with the key mode the surrounding
  prose claims** (`tpm2` vs `host` — a block that says one and does the other is
  a security defect; the match is token-anchored so `host` cannot pass on
  `host+tpm2`), and `op read` failure aborts before `ssh`.
- **`run:secretspec`** (Appendix B.3) — same invariants, plus the appendix's one
  hard rule: the block must call `secretspec get` (value to stdout) and must
  **not** call `secretspec run` (env injection). The stub *implements* `run`, so
  that rule is enforced by policy rather than by an unimplemented stub.

Assertion messages report *shape only* (byte/line counts, first token) — never
the captured stream content, which in a real run would be a secret.

## Mutation-tested

The assertions were verified by reintroducing each bug Daria found and
confirming a failure (all also verified with `shellcheck` absent from `PATH`):

| Mutation | Caught by |
|---|---|
| Drop a `doctest=` annotation | `no doctest= annotation` |
| Inline `# comment` in `ssh_config` | `sshconfig` static check |
| `op inject \| ssh` naive pipeline | `ssh ran even though op inject failed` |
| `sh -c 'env'` instead of `op inject` | `stdin mismatch — expected 2 line(s)` |
| EIC path mismatch + no `trap` | `aws` stub: pubkey path does not exist |
| Secret passed in remote argv | `secret leaked into ssh argv` |
| Phase 4.1 downgraded to `--with-key=host` | `expected --with-key=tpm2` |
| Appendix A.1 silently seals to `tpm2` | `expected --with-key=host` |
| Appendix A.1 seals to `host+tpm2` (was a false pass) | `expected --with-key=host (exactly)` |
| Closing fence with trailing text swallows the next block | `FATAL: … closing fence has trailing text` |
| Fence inside a blockquote | `FATAL: … not supported (move it out)` |
| Malformed `op://` ref in the env template | `not a KEY=op://vault/item/field reference` |
| Secret hardcoded, `op`/`secretspec` called decoratively | `values are not the ones … returned (hardcoded?)` |
| Appendix B uses `secretspec run` (env injection) | env-dump keys on stdin / `used secretspec run` |

## Limits

- The `run:*` scenarios verify the **laptop side** contract (what crosses the
  wire, what lands in argv, what is cleaned up). They do not prove the remote
  systemd behavior; `unit` mode's `systemd-analyze verify` covers unit syntax
  only, and only on Linux.
- `LoadCredential`/`LoadCredentialEncrypted` semantics, TPM sealing, and ramfs
  behavior can only be validated on a real NitroTPM instance. That is
  deliberately out of scope here and called out in the guide.
