#!/usr/bin/env bash
# remote-tests.sh — runs ON a NitroTPM EC2 instance, as root, via SSM.
#
# Verifies the claims in the guide that the laptop-side doctest tier explicitly
# cannot: TPM sealing, LoadCredentialEncrypted delivery, ramfs semantics of
# $CREDENTIALS_DIRECTORY, and the IMDSv2 / Parameter-Store-Deny posture.
#
# Never printed: the canary value. Assertions report shape only, exactly as the
# doctest harness does, so a captured log can never leak what was sealed.
#
# Ship it with: test/instance/run-instance-tests.sh
set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

readonly CRED_DIR='/etc/credstore.encrypted'
readonly HOST_KEY='/var/lib/systemd/credential.secret'
readonly HOST_KEY_BAK='/var/lib/systemd/credential.secret.dh-bak'
# Per-run unit name so back-to-back runs never collide on --unit=. $$ is the
# script's PID on the instance; set once in main().
UNIT=''

PASS=0
FAIL=0
SKIP=0
WORK=''
NONCE=''
TPM2_USABLE=false

ok()   { printf 'ok    %s\n' "$1"; PASS=$((PASS + 1)); }
no()   { printf 'FAIL  %s\n' "$1"; FAIL=$((FAIL + 1)); }
skip() { printf 'skip  %s\n' "$1"; SKIP=$((SKIP + 1)); }
note() { printf '      %s\n' "$1"; }

cleanup() {
    # Restore the host key first: leaving it moved would break every service
    # that uses systemd credentials on this box.
    if [[ -f "${HOST_KEY_BAK}" ]]; then
        mv -f "${HOST_KEY_BAK}" "${HOST_KEY}" || true
    fi
    if [[ -n "${UNIT}" ]]; then
        systemctl stop "${UNIT}.service" 2>/dev/null || true
        systemctl reset-failed "${UNIT}.service" 2>/dev/null || true
    fi
    [[ -n "${WORK}" && -d "${WORK}" ]] && rm -rf "${WORK}"
    return 0
}
trap cleanup EXIT

# `tr < /dev/urandom | head -c N` takes SIGPIPE and pipefail makes that fatal.
new_nonce() { LC_ALL=C od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }

# ---------------------------------------------------------------- environment

require_root() {
    (($(id -u) == 0)) || { printf 'FATAL: must run as root\n' >&2; exit 1; }
}

# =============================================================== Phase 2.2 ===

t_has_tpm2() {
    if systemd-creds has-tpm2 --quiet; then
        ok 'systemd-creds has-tpm2 exits 0'
    else
        no "systemd-creds has-tpm2 exited $? (guide Phase 2.2)"
    fi

    if [[ -c /dev/tpmrm0 ]]; then
        ok '/dev/tpmrm0 is a character device'
    else
        no '/dev/tpmrm0 missing — this is not a NitroTPM instance'
    fi
}

t_swap_off() {
    local lines
    lines="$(swapon --show | wc -l)"
    if ((lines == 0)); then
        ok 'swap is off (swapon --show is empty)'
    else
        no "swap is active (${lines} line(s)) — decrypted memory can page to disk"
    fi
}

t_coredump_storage_none() {
    # The guide tells the operator to install this drop-in. Install it, then
    # assert systemd's *effective* config picks it up.
    mkdir -p /etc/systemd/coredump.conf.d
    printf '[Coredump]\nStorage=none\n' > /etc/systemd/coredump.conf.d/no-storage.conf

    local effective
    effective="$(systemd-analyze cat-config systemd/coredump.conf 2>/dev/null \
        | grep -E '^[[:space:]]*Storage=' | tail -n 1 | tr -d '[:space:]')"

    if [[ "${effective}" == 'Storage=none' ]]; then
        ok 'coredump.conf drop-in yields effective Storage=none'
    else
        no "effective coredump Storage is '${effective:-<unset>}', expected Storage=none"
    fi
}

# =============================================================== Phase 4.1 ===

# The finding this whole tier exists to surface. `has-tpm2` can pass on every
# component while `systemd-creds encrypt --with-key=tpm2` still fails, because
# systemd dlopen()s the tpm2-tss runtime libraries and stock AL2023 ships none.
# So the only honest readiness check is an actual seal. If it fails, that is a
# real defect against the current guide; we then install tpm2-tss so the rest of
# the suite can exercise the sealing path, but the FAIL stands.
t_tpm2_seal_requires_tss() {
    if printf 'x' | systemd-creds encrypt --name=probe --with-key=tpm2 \
        - "${WORK}/probe.cred" 2>/dev/null; then
        rm -f "${WORK}/probe.cred"
        TPM2_USABLE=true
        ok 'systemd-creds --with-key=tpm2 seals out of the box'
        return 0
    fi

    no 'has-tpm2 passes but --with-key=tpm2 fails — tpm2-tss runtime libs missing'
    note 'the guide Phase 2.2 has-tpm2 check is not sufficient; an actual seal is'

    if command -v dnf >/dev/null 2>&1 && dnf install -y tpm2-tss >/dev/null 2>&1 \
        && printf 'x' | systemd-creds encrypt --name=probe --with-key=tpm2 \
            - "${WORK}/probe.cred" 2>/dev/null; then
        rm -f "${WORK}/probe.cred"
        TPM2_USABLE=true
        note 'installing tpm2-tss fixed it — that package is the missing prerequisite'
    else
        note 'tpm2 sealing still broken after attempting to install tpm2-tss'
    fi
}

# The remote half of the guide's 4.1 block, byte for byte.
seal_tpm2() {
    mkdir -p "${CRED_DIR}"
    systemd-creds encrypt --name=db-password --with-key=tpm2 \
        - "${CRED_DIR}/db-password.cred"
}

t_seal_and_decrypt_tpm2() {
    if ! "${TPM2_USABLE}"; then
        skip 'seal/decrypt round-trip (tpm2 sealing unavailable)'
        return 0
    fi
    if ! printf '%s' "${NONCE}" | seal_tpm2; then
        no 'systemd-creds encrypt --with-key=tpm2 failed (guide Phase 4.1)'
        return 0
    fi
    ok 'sealed a credential with --with-key=tpm2 from stdin'

    local got
    # --name is required: without it, decrypt validates the embedded name against
    # the filename (db-password vs db-password.cred) and refuses. The guide never
    # bare-decrypts; it consumes via LoadCredentialEncrypted=db-password:... which
    # supplies the name, matching this.
    if ! got="$(systemd-creds decrypt --name=db-password "${CRED_DIR}/db-password.cred" -)"; then
        no 'systemd-creds decrypt failed on this instance'
        return 0
    fi
    if [[ "${got}" == "${NONCE}" ]]; then
        ok 'decrypt round-trips the exact bytes that were piped in'
    else
        no "decrypt returned ${#got} byte(s), expected ${#NONCE}"
    fi
}

t_ciphertext_is_opaque() {
    local blob="${CRED_DIR}/db-password.cred"
    [[ -f "${blob}" ]] || { skip 'ciphertext opacity (no blob)'; return 0; }

    # -a: the canary is hex, so a plaintext copy would show up as ASCII.
    if grep -qa -- "${NONCE}" "${blob}"; then
        no 'the sealed file contains the plaintext canary'
    else
        ok 'sealed file does not contain the plaintext'
    fi
}

# The load-bearing claim of Phase 4.1: with --with-key=tpm2, "nothing on disk
# contributes to decryption". We cannot mount this volume on another instance
# from here, so we test the property that makes that true — remove every scrap
# of on-disk key material and the tpm2 blob must still open, while a host blob
# must not.
t_tpm2_does_not_use_disk_key() {
    if ! "${TPM2_USABLE}"; then
        skip 'tpm2-vs-host key separation (tpm2 sealing unavailable)'
        return 0
    fi
    local d="${WORK}/keysep"
    mkdir -p "${d}"

    # --with-key=host creates the on-disk key as a side effect. That is exactly
    # the property Appendix A warns about: ciphertext and key travel together.
    if ! printf '%s' "${NONCE}" | systemd-creds encrypt --name=t-host \
        --with-key=host - "${d}/host.cred"; then
        no 'could not seal a --with-key=host control blob'
        return 0
    fi
    if [[ -f "${HOST_KEY}" ]]; then
        ok "--with-key=host wrote on-disk key material (${HOST_KEY})"
    else
        no "--with-key=host did not create ${HOST_KEY} — assumption broken"
        return 0
    fi

    if ! printf '%s' "${NONCE}" | systemd-creds encrypt --name=t-tpm2 \
        --with-key=tpm2 - "${d}/tpm2.cred"; then
        no 'could not seal a --with-key=tpm2 blob'
        return 0
    fi

    mv "${HOST_KEY}" "${HOST_KEY_BAK}"   # cleanup() restores this on any exit

    local got
    if got="$(systemd-creds decrypt --name=t-tpm2 "${d}/tpm2.cred" - 2>/dev/null)" \
        && [[ "${got}" == "${NONCE}" ]]; then
        ok 'tpm2 blob decrypts with the on-disk key removed'
    else
        no 'tpm2 blob failed to decrypt without the on-disk key — it is not TPM-only'
    fi

    if systemd-creds decrypt --name=t-host "${d}/host.cred" - >/dev/null 2>&1; then
        no 'host blob decrypted without the on-disk key — control is broken'
    else
        ok 'host blob does NOT decrypt without the on-disk key (Appendix A)'
    fi

    mv -f "${HOST_KEY_BAK}" "${HOST_KEY}"

    if got="$(systemd-creds decrypt --name=t-host "${d}/host.cred" - 2>/dev/null)" \
        && [[ "${got}" == "${NONCE}" ]]; then
        ok 'host blob decrypts again once the on-disk key is back'
    else
        no 'host blob did not decrypt after restoring the on-disk key'
    fi
}

# =============================================================== Phase 4.2 ===

t_load_credential_encrypted() {
    local blob="${CRED_DIR}/db-password.cred"
    [[ -f "${blob}" ]] || { skip 'LoadCredentialEncrypted (no blob)'; return 0; }

    local got
    # shellcheck disable=SC2016  # $CREDENTIALS_DIRECTORY must expand on the unit, not here
    if ! got="$(systemd-run --wait --pipe --collect --quiet \
        -p "LoadCredentialEncrypted=db-password:${blob}" \
        /bin/sh -c 'cat "$CREDENTIALS_DIRECTORY/db-password"' 2>/dev/null)"; then
        no 'LoadCredentialEncrypted= did not start the unit'
        return 0
    fi
    if [[ "${got}" == "${NONCE}" ]]; then
        ok 'LoadCredentialEncrypted= delivers the decrypted credential'
    else
        no "credential in \$CREDENTIALS_DIRECTORY was ${#got} byte(s), expected ${#NONCE}"
    fi
}

t_credentials_dir_is_ramfs() {
    local blob="${CRED_DIR}/db-password.cred"
    [[ -f "${blob}" ]] || { skip 'ramfs check (no blob)'; return 0; }

    local fstype
    # shellcheck disable=SC2016  # $CREDENTIALS_DIRECTORY must expand on the unit, not here
    fstype="$(systemd-run --wait --pipe --collect --quiet \
        -p "LoadCredentialEncrypted=db-password:${blob}" \
        /bin/sh -c 'stat -f -c %T "$CREDENTIALS_DIRECTORY"' 2>/dev/null || true)"

    if [[ "${fstype}" == 'ramfs' ]]; then
        ok 'the credentials directory is ramfs (never swaps, never hits disk)'
    else
        no "\$CREDENTIALS_DIRECTORY is '${fstype:-<unknown>}', expected ramfs"
    fi
}

t_credentials_dir_is_private() {
    local blob="${CRED_DIR}/db-password.cred"
    [[ -f "${blob}" ]] || { skip 'privacy check (no blob)'; return 0; }

    systemctl reset-failed "${UNIT}.service" 2>/dev/null || true
    if ! systemd-run --unit="${UNIT}" --quiet \
        -p "LoadCredentialEncrypted=db-password:${blob}" \
        /bin/sleep 30 2>/dev/null; then
        no 'could not start the long-running credential unit'
        return 0
    fi

    local dir="/run/credentials/${UNIT}.service"
    local i=0
    while ((i < 20)) && [[ ! -d "${dir}" ]]; do sleep 0.2; i=$((i + 1)); done

    if [[ ! -d "${dir}" ]]; then
        no "credentials directory ${dir} never appeared"
        systemctl stop "${UNIT}.service" 2>/dev/null || true
        return 0
    fi

    local dmode
    dmode="$(stat -c '%a' "${dir}")"
    if [[ "${dmode}" == '700' ]]; then
        ok "credentials directory is mode 0700 (root-only)"
    else
        no "credentials directory is mode 0${dmode}, expected 0700"
    fi

    local runner=''
    if command -v setpriv >/dev/null 2>&1; then
        runner='setpriv --reuid=65534 --regid=65534 --clear-groups'
    elif command -v runuser >/dev/null 2>&1; then
        runner='runuser -u nobody --'
    fi

    if [[ -z "${runner}" ]]; then
        skip 'non-root read of the credentials directory (no setpriv/runuser)'
    elif ${runner} cat "${dir}/db-password" >/dev/null 2>&1; then
        no 'a non-root user read the decrypted credential'
    else
        ok 'a non-root user cannot read the decrypted credential'
    fi

    systemctl stop "${UNIT}.service" 2>/dev/null || true
    i=0
    while ((i < 20)) && [[ -d "${dir}" ]]; do sleep 0.2; i=$((i + 1)); done
    if [[ -d "${dir}" ]]; then
        no 'credentials directory survived unit stop'
    else
        ok 'credentials directory is torn down when the unit stops'
    fi
}

# Regression test for Daria finding B1. The guide originally said
# `LoadCredential=envblock:/dev/stdin`. LoadCredential's path is opened by the
# service *manager* (PID 1), whose stdin is not the pipe you wrote to, so the
# secret never arrives. This must be tested WITHOUT `systemd-run --pipe`: --pipe
# wires the caller's pipe to the unit's stdin, which makes /dev/stdin resolve to
# the pipe and would mask the very bug B1 describes. We pipe to a plain
# systemd-run instead, and have the (root) unit record what it actually received
# into a root-owned file under WORK. Empty/missing => the secret did not arrive,
# so the finding holds.
t_load_credential_stdin_does_not_work() {
    local out="${WORK}/b1-received"
    rm -f "${out}"

    # No --pipe. The transient unit is created over D-Bus by PID 1; our pipe is
    # not inherited by it. shellcheck: $CREDENTIALS_DIRECTORY expands on the unit.
    # shellcheck disable=SC2016
    printf '%s' "${NONCE}" | systemd-run --wait --collect --quiet \
        -p 'LoadCredential=canary:/dev/stdin' \
        /bin/sh -c "cat \"\$CREDENTIALS_DIRECTORY/canary\" > '${out}' 2>/dev/null || true" \
        >/dev/null 2>&1 || true

    local got=''
    [[ -f "${out}" ]] && got="$(cat "${out}")"

    if [[ "${got}" == "${NONCE}" ]]; then
        no 'LoadCredential=:/dev/stdin delivered the piped secret — finding B1 is stale'
    else
        ok "LoadCredential=:/dev/stdin did not deliver the secret (${#got} byte(s)) — B1 holds"
    fi
}

# =============================================================== Phase 3 =====

t_systemd_run_pipe_delivers_stdin() {
    local got
    got="$(printf '%s' "${NONCE}" | systemd-run --wait --pipe --collect --quiet \
        -p MemorySwapMax=0 -p LimitCORE=0 -p PrivateTmp=yes \
        /bin/cat 2>/dev/null || true)"

    if [[ "${got}" == "${NONCE}" ]]; then
        ok 'systemd-run --pipe delivers stdin to the unit (Phase 3 Track A)'
    else
        no "systemd-run --pipe delivered ${#got} byte(s), expected ${#NONCE}"
    fi
}

t_hardening_properties_apply() {
    local core
    core="$(systemd-run --wait --pipe --collect --quiet -p LimitCORE=0 \
        /bin/sh -c 'ulimit -c' 2>/dev/null || true)"
    if [[ "${core}" == '0' ]]; then
        ok 'LimitCORE=0 reaches the unit (ulimit -c is 0)'
    else
        no "unit saw core limit '${core:-<none>}', expected 0"
    fi

    local swapmax
    # Read the unit's OWN cgroup file, not the root cgroup (which has no
    # memory.swap.max). /proc/self/cgroup field 3 is the v2 path.
    # shellcheck disable=SC2016  # the $() must run inside the unit's sh
    swapmax="$(systemd-run --wait --pipe --collect --quiet -p MemorySwapMax=0 \
        /bin/sh -c 'cat "/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/memory.swap.max" 2>/dev/null' 2>/dev/null || true)"
    if [[ "${swapmax}" == '0' ]]; then
        ok 'MemorySwapMax=0 reaches the unit cgroup'
    elif [[ -z "${swapmax}" ]]; then
        skip 'MemorySwapMax=0 (no cgroup v2 memory.swap.max)'
    else
        no "unit cgroup memory.swap.max is '${swapmax}', expected 0"
    fi
}

# =============================================================== Phase 5 =====

t_imdsv2_required() {
    local code
    code="$(curl -s -m 3 -o /dev/null -w '%{http_code}' \
        http://169.254.169.254/latest/meta-data/ 2>/dev/null || true)"
    if [[ "${code}" == '401' ]]; then
        ok 'IMDSv1 is refused (HTTP 401) — HttpTokens=required'
    else
        no "unauthenticated IMDS returned HTTP ${code:-<none>}, expected 401"
    fi

    local token
    token="$(curl -s -m 3 -X PUT http://169.254.169.254/latest/api/token \
        -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || true)"
    if [[ -n "${token}" ]]; then
        ok 'IMDSv2 token endpoint works'
    else
        no 'could not obtain an IMDSv2 token'
    fi
}

# The instance role is AmazonSSMManagedInstanceCore, which grants ssm:GetParameter
# on "Resource": "*". create-test-instance.sh attaches an inline Deny to claw that
# back. Root on this box must not be able to read Parameter Store.
t_parameter_store_denied() {
    if ! command -v aws >/dev/null 2>&1; then
        skip 'Parameter Store Deny (no aws CLI on the instance)'
        return 0
    fi

    local region out rc=0
    region="$(curl -s -m 3 -H "X-aws-ec2-metadata-token: $(curl -s -m 3 -X PUT \
        http://169.254.169.254/latest/api/token \
        -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" \
        http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || true)"
    [[ -n "${region}" ]] || { skip 'Parameter Store Deny (no region from IMDS)'; return 0; }

    out="$(aws ssm get-parameter --region "${region}" \
        --name '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64' \
        2>&1)" || rc=$?

    if ((rc == 0)); then
        no 'the instance role CAN read Parameter Store — the inline Deny is not in effect'
    elif [[ "${out}" == *'AccessDenied'* || "${out}" == *'not authorized'* ]]; then
        ok 'the instance role cannot read Parameter Store (inline Deny in effect)'
    else
        skip "Parameter Store Deny (aws failed for another reason, rc=${rc})"
    fi
}

# ---------------------------------------------------------------------- main

main() {
    require_root
    WORK="$(mktemp -d "${TMPDIR:-/tmp}/dh-instance.XXXXXX")"
    NONCE="$(new_nonce)"
    UNIT="dh-credtest-$$"

    printf '# dev-harden instance tests — %s\n' "$(uname -srm)"
    printf '# canary is %s bytes; its value is never printed\n\n' "${#NONCE}"

    t_has_tpm2
    t_swap_off
    t_coredump_storage_none
    t_tpm2_seal_requires_tss
    t_seal_and_decrypt_tpm2
    t_ciphertext_is_opaque
    t_tpm2_does_not_use_disk_key
    t_load_credential_encrypted
    t_credentials_dir_is_ramfs
    t_credentials_dir_is_private
    t_load_credential_stdin_does_not_work
    t_systemd_run_pipe_delivers_stdin
    t_hardening_properties_apply
    t_imdsv2_required
    t_parameter_store_denied

    printf '\n# pass %d  fail %d  skip %d\n' "${PASS}" "${FAIL}" "${SKIP}"
    ((FAIL == 0)) || return 1
    return 0
}

main "$@"
