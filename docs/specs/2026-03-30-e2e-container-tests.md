# spec: End-to-End Container Tests

## Overview

A test harness that runs the existing BATS test suite inside Docker/Podman containers across multiple Linux distributions. A developer invokes a single command (`test/e2e.sh`) and gets a pass/fail result per distro, confirming that `git-harden.sh` works correctly on each target platform.

## Purpose

Catch platform-specific regressions that the host-only BATS tests cannot surface: different default git versions, missing utilities, musl vs glibc edge cases, different `sed`/`grep` flavors, and package-layout differences (e.g. `git-credential-libsecret` paths).

### Non-Goals

- Testing macOS in containers (no official macOS Docker images; macOS is covered by running BATS on the host).
- Testing FIDO2 hardware key prompts (requires physical security key; cannot be simulated).
- CI/CD pipeline integration (GitHub Actions matrix YAML) -- that can be layered on later without spec changes.
- Building or publishing container images for end users.
- Testing with real SSH keys or real remotes.

## User Stories

**As a** contributor
**I want** to run `test/e2e.sh` and see per-distro pass/fail output
**So that** I know the script works on all supported Linux distributions before merging.

**As a** contributor
**I want** to run tests against a single distro for faster iteration
**So that** I can debug a platform-specific failure without waiting for the full matrix.

## Functional Requirements

### Runner Script (`test/e2e.sh`)

- Accepts an optional `--runtime` flag: `docker` (default) or `podman`. Auto-detects if only one is installed.
- Accepts an optional positional argument to run a single distro by name (e.g. `test/e2e.sh alpine`).
- Without arguments, runs all distros in the matrix sequentially and prints a summary table at the end.
- Exit code: 0 if all distros pass, 1 if any distro fails, 1 if the container runtime is not installed.
- Each distro run builds a container image (if not cached) and executes `test/run.sh` inside it.
- Passes `--tap` to BATS so output is machine-readable; the runner reformats it into a human-friendly per-distro summary.
- Build context is the repo root; only the files needed for testing are copied (script, test dir, submodules).

### Containerfiles (`test/containers/`)

- One `Containerfile.<distro>` per target distro. Each file:
  1. Starts from the distro's official base image, pinned to a specific release tag (not `latest`).
  2. Installs the minimum packages: `bash`, `git` (>= 2.34), `openssh` (client + `ssh-keygen`), `tmux`.
  3. Creates a non-root test user and switches to it.
  4. Copies `git-harden.sh` and `test/` into the image.
  5. Sets `CMD` to `test/run.sh`.

### Distro Matrix

| Name | Base Image | Package Manager | Notes |
|------|-----------|-----------------|-------|
| `ubuntu` | `ubuntu:24.04` | apt-get | Mainstream deb-based |
| `debian` | `debian:trixie` | apt-get | Upcoming stable (Debian 13) |
| `fedora` | `fedora:42` | dnf | rpm-based |
| `alpine` | `alpine:3.21` | apk | musl libc, BusyBox coreutils |
| `arch` | `archlinux:base` | pacman | Rolling release, latest packages |

### Interactive Testing via `tmux`

The signing wizard and interactive apply flow read from `/dev/tty`, which does not exist in a container by default. Instead of `expect` (TCL), interactive tests use `tmux send-keys` to drive the prompts. This keeps all test code in bash, consistent with the rest of the project.

#### How it works

1. `tmux` is installed in every container alongside the other test dependencies.
2. Interactive test scripts live in `test/interactive/` as plain bash scripts.
3. Each script starts a `tmux` session, runs `git-harden.sh` inside it, and drives the interaction:
   - `tmux new-session -d -s test "bash /path/to/git-harden.sh"` -- starts the script in a detached session with a real tty.
   - A `wait_for` helper polls `tmux capture-pane -t test -p` until a pattern appears (or a timeout fires, defaulting to 10 seconds).
   - `tmux send-keys -t test "y" Enter` -- sends keystrokes to the session.
   - After the script exits, `tmux capture-pane` captures the final output for assertions.
4. No `--tty` flag needed on `docker run` / `podman run` -- `tmux` creates its own pseudo-terminal inside the container.

#### `wait_for` helper

```bash
# Wait for a string to appear in the tmux pane. Polls every 0.2s, times out after $2 seconds (default 10).
wait_for() {
    local pattern="$1"
    local timeout="${2:-10}"
    local elapsed=0
    while ! tmux capture-pane -t test -p | grep -qF "$pattern"; do
        sleep 0.2
        elapsed=$(( elapsed + 1 ))
        if (( elapsed > timeout * 5 )); then
            printf 'TIMEOUT waiting for: %s\n' "$pattern" >&2
            tmux capture-pane -t test -p >&2
            return 1
        fi
    done
}
```

#### Interactive scenarios to cover

**Note:** Every interactive run hits the **safety review gate** first ("Have you reviewed this script...?"). All scenarios below must send `y` + Enter to pass the gate before reaching the audit/apply flow.

| Scenario | `tmux send-keys` sequence | Verifies |
|----------|---------------------------|----------|
| Full interactive apply (accept all) | `y` + Enter (safety gate), `y` + Enter (proceed with hardening), `y` + Enter to each setting prompt | All settings applied; re-audit exits 0 |
| Interactive apply (decline some) | `y` + Enter (safety gate), `y` + Enter (proceed), then `n` + Enter for specific prompts | Declined settings remain unchanged |
| Safety gate decline | `n` + Enter (safety gate) | Script exits 0; prints AI review instructions; no config changes |
| Signing wizard: generate ed25519 key | `y` + Enter (safety gate), then through apply prompts, `1` + Enter for menu, Enter for empty passphrase (twice) | Key created at `~/.ssh/id_ed25519.pub`; signing config set |
| Signing wizard: use existing key | `y` + Enter (safety gate), then through apply prompts, `y` + Enter when prompted "Use this key?" | `user.signingkey` set to the existing key path |
| Signing wizard: skip | `y` + Enter (safety gate), then through apply prompts, `s` + Enter for menu | No signing key configured; `commit.gpgsign` not set |

#### What is NOT tested interactively

- FIDO2 key generation (`ssh-keygen -t ed25519-sk`) -- requires physical hardware token touch.
- Real passphrase entry with confirmation -- tests use empty passphrases to keep scripts simple.

### Test Isolation

- The existing BATS tests already create a fresh `$HOME` via `mktemp` per test. No changes to the test suite are required.
- Containers run with `--network=none` -- the tests do not need network access, and this prevents accidental external calls.
- Containers are removed after each run (`--rm`).

## Edge Cases & Error States

### Input Boundaries

| Condition | Expected Behavior |
|-----------|-------------------|
| Unknown distro name passed | Print available distros and exit 1 |
| Neither docker nor podman installed | Print clear error with install hint and exit 1 |
| `--runtime` points to missing binary | Print error naming the binary and exit 1 |

### Failure Modes

| Failure | Response |
|---------|----------|
| Container build fails (e.g. package 404) | Print build log, mark distro as FAIL, continue to next |
| BATS tests fail inside container | Capture TAP output, mark distro as FAIL, continue to next |
| Container runtime daemon not running | Print clear error ("Is the Docker/Podman daemon running?") and exit 1 |
| Disk full during image build | Container runtime's own error propagates; distro marked FAIL |

### Security Boundaries

| Threat | Mitigation |
|--------|------------|
| Container escapes host filesystem | `--network=none`, non-root user, no volume mounts (files are `COPY`'d) |
| Stale base images with CVEs | Pinned image tags; updating tags is a deliberate, reviewable change |

## Non-Functional Requirements

### Performance

- Full matrix (5 distros, cold build): under 5 minutes on a machine with a reasonable internet connection.
- Full matrix (warm cache, images already built): under 60 seconds.
- Single distro (warm cache): under 15 seconds.

### Portability

- `test/e2e.sh` itself must pass `shellcheck` and follow the project's shell standards (AGENTS.md).
- Works with Docker Engine >= 20.10 and Podman >= 4.0.
- `Containerfile` syntax (not `Dockerfile`) for Podman compatibility; Docker handles this fine too.

## Pre-Mortem

### Likely Failure Modes

| Failure | Why It Could Happen |
|---------|---------------------|
| Alpine tests fail due to BusyBox `sed`/`grep` differences | `git-harden.sh` uses `sed` and `grep` features that differ between GNU and BusyBox |
| Arch image breaks on next pacman keyring rotation | Rolling distro; base image may need periodic tag bumps |
| `wait_for` polling misses fast prompts or races | Prompt appears and is overwritten before `capture-pane` sees it, or script advances before `send-keys` arrives |
| `tmux` version differences across distros | Older tmux may lack `capture-pane -p` flag or have different `send-keys` behavior |
| BATS submodules missing in container | Build context doesn't include submodule contents |

### Mitigations

| Failure | Addressed By | Status |
|---------|--------------|--------|
| BusyBox incompatibilities | Testing on Alpine surfaces these; fixes go into `git-harden.sh` | Mitigated |
| Arch keyring breakage | Pinned to `archlinux:base` (monthly snapshots); update in a PR when needed | Accepted Risk |
| `wait_for` race conditions | 0.2s polling interval is fast enough for human-speed prompts; `git-harden.sh` blocks on `read` so prompts persist until input arrives | Mitigated |
| tmux version differences | `capture-pane -p` available since tmux 1.8 (2013); all target distros ship tmux >= 3.x | Mitigated |
| Missing BATS submodules | Containerfile copies `test/libs/` explicitly; build-time check | Mitigated |

## Acceptance Criteria

### Must Have

- [ ] **`test/e2e.sh` runs full matrix and reports per-distro results**
  - Given: Docker or Podman is installed and running
  - When: `test/e2e.sh` is invoked with no arguments
  - Then: All 5 distros are tested; output shows PASS/FAIL per distro; exit code reflects overall result

- [ ] **Single-distro mode works**
  - Given: Docker or Podman is installed
  - When: `test/e2e.sh ubuntu` is invoked
  - Then: Only the Ubuntu container is built and tested

- [ ] **`--runtime` flag selects container engine**
  - Given: Both Docker and Podman are installed
  - When: `test/e2e.sh --runtime podman`
  - Then: Podman is used exclusively

- [ ] **All existing BATS tests pass on every distro in the matrix**
  - Given: Containers are built from Containerfiles
  - When: `test/run.sh` executes inside each container
  - Then: All tests pass (exit 0) on Ubuntu, Debian, Fedora, Alpine, and Arch

- [ ] **Containers run with no network and no root**
  - Given: Any distro container
  - When: Inspecting the `docker run` / `podman run` command
  - Then: `--network=none` is set and the test user is non-root

- [ ] **Runner handles missing container runtime gracefully**
  - Given: Neither docker nor podman is on `$PATH`
  - When: `test/e2e.sh` is invoked
  - Then: Prints actionable error and exits 1

- [ ] **`test/e2e.sh` passes shellcheck**
  - Given: The runner script exists
  - When: `shellcheck test/e2e.sh` is run
  - Then: No warnings or errors

- [ ] **Interactive apply flow works end-to-end via `tmux`**
  - Given: A container with no prior git hardening and `tmux` installed
  - When: `tmux`-driven script runs `git-harden.sh` (no flags), answering `y` to safety review gate, then `y` to all subsequent prompts
  - Then: All settings applied; `git-harden.sh --audit` exits 0 afterward

- [ ] **Safety review gate decline exits cleanly**
  - Given: A container with `tmux` installed
  - When: `tmux`-driven script runs `git-harden.sh` (no flags), answering `n` to safety review gate
  - Then: Script exits 0; output contains AI review instructions; no config changes made

- [ ] **Signing wizard key generation works via `tmux`**
  - Given: A container with no existing SSH keys
  - When: `tmux`-driven script runs `git-harden.sh`, selects option 1 (generate ed25519), provides empty passphrase
  - Then: `~/.ssh/id_ed25519.pub` exists; `user.signingkey` is configured; `commit.gpgsign=true`

- [ ] **Signing wizard skip leaves signing unconfigured**
  - Given: A container with no existing SSH keys
  - When: `tmux`-driven script runs `git-harden.sh`, selects `s` (skip) at signing menu
  - Then: `user.signingkey` is not set; `commit.gpgsign` is not set

### Should Have

- [ ] **Build failures don't abort the full matrix**
  - Given: One distro's Containerfile has a broken package install
  - When: `test/e2e.sh` runs the full matrix
  - Then: The broken distro is marked FAIL; remaining distros still run

- [ ] **Summary table at end of full run**
  - Given: Full matrix completes
  - When: Runner finishes
  - Then: A table showing distro name + PASS/FAIL + duration is printed to stderr

### Could Have

- [ ] Parallel distro execution (run containers concurrently for faster feedback)
- [ ] `--rebuild` flag to force image rebuild ignoring cache

### Won't Have (This Release)

- [ ] GitHub Actions / CI integration (separate concern, separate spec)
- [ ] macOS container testing
- [ ] Windows container testing
- [ ] Automatic base image tag bumping / Dependabot-style updates
