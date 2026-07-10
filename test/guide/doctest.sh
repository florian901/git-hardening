#!/usr/bin/env bash
# doctest.sh — "Elixir doctest" style harness for the EC2/1Password guide.
#
# Extracts EVERY fenced code block from the guide and dispatches it by the
# doctest=<mode> annotation on its info string:
#   syntax      bash -n, non-empty, and at least one recognized command word
#   script      bash -n + shellcheck (a complete script)
#   sshconfig   no inline comments, then parsed by the real `ssh -G -F`
#   toml        parsed with python3 tomllib
#   ini         static INI/systemd-syntax validation
#   unit        static validation + `systemd-analyze verify` where available
#   envtpl      every line is a KEY=op://vault/item[/section]/field reference
#   run:<name>  bash -n + shellcheck, then EXECUTED against stub op/aws/ssh
#               binaries with per-scenario security assertions
#
# COVERAGE GUARANTEE, stated precisely:
#   * A fenced block without a doctest= annotation FAILS.
#   * There is no opt-out mode. Every block gets a checker.
#   * Markdown the extractor cannot parse unambiguously (blockquoted fences,
#     tab-indented fences, malformed closing fences, unterminated blocks) is a
#     HARD ERROR, never a silent skip. Invisibility is the failure mode this
#     harness exists to prevent, so it must be impossible.
#
# What `syntax` mode does NOT prove: that a command is correct, only that it
# parses as bash and names a tool the guide claims to use. Illustrative blocks
# get illustrative checks; the security-relevant blocks are `run:*`.
set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly SCRIPT_DIR
readonly GUIDE="${1:-${SCRIPT_DIR}/../../docs/guides/2026-07-09-ec2-1password-zero-plaintext-guide.md}"
readonly STUBS_DIR="${SCRIPT_DIR}/stubs"
# BSD `-t` takes a prefix; GNU `-t` is deprecated and rejects a template with
# no X's. An explicit template behaves identically on both.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/guide-doctest.XXXXXX")"
readonly WORK

# Commands the guide legitimately demonstrates. A `syntax` block must invoke at
# least one of them, so prose or an empty block cannot pass vacuously.
readonly KNOWN_COMMANDS='aws|op|secretspec|brew|ssh|ssh-keygen|systemd-creds|systemd-run|swapon|stat|sudo'

HAVE_SHELLCHECK=false
HAVE_SSH=false
HAVE_PYTHON_TOML=false
HAVE_SYSTEMD_ANALYZE=false

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

cleanup() {
    rm -rf "${WORK}"
}
trap cleanup EXIT

die() {
    printf 'FATAL: %s\n' "$*" >&2
    exit 1
}

report() {
    local status="$1" block="$2" mode="$3" detail="${4:-}"
    printf '%-4s block %s (line %s, %s)%s\n' \
        "${status}" "${block%%:*}" "${block##*:}" "${mode}" \
        "${detail:+ — ${detail}}" >&2
    case "${status}" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac
}

probe_tools() {
    command -v shellcheck       >/dev/null && HAVE_SHELLCHECK=true
    command -v ssh              >/dev/null && HAVE_SSH=true
    command -v systemd-analyze  >/dev/null && HAVE_SYSTEMD_ANALYZE=true
    if command -v python3 >/dev/null && python3 -c 'import tomllib' 2>/dev/null; then
        HAVE_PYTHON_TOML=true
    fi
    return 0
}

# --- extraction -------------------------------------------------------------
#
# Fence handling is deliberately strict. The close must use the same fence
# character, be at least as long as the opener, be indented no further, and
# carry nothing but whitespace after it. Anything else is a hard error, because
# a mis-paired fence silently swallows the following block — which would
# disable its tests while the summary still reads green.

extract_blocks() {
    awk -v out="${WORK}" -v manifest="${WORK}/manifest" -v errfile="${WORK}/extract_errors" '
        function fail(msg) { printf "%s\n", msg >> errfile; err = 1 }
        function fence_len(s, ch,    k) {
            k = 0
            while (substr(s, k + 1, 1) == ch) k++
            return k
        }
        BEGIN { n = 0; inb = 0; err = 0 }

        # Constructs we cannot parse unambiguously — refuse rather than ignore.
        inb == 0 && /^[[:space:]]*>[[:space:]]*(```|~~~)/ {
            fail("line " NR ": fenced block inside a blockquote is not supported (move it out)")
            next
        }
        inb == 0 && /^\t+(```|~~~)/ {
            fail("line " NR ": tab-indented fence is not supported (use spaces)")
            next
        }

        # Opening fence.
        inb == 0 && /^ *(```|~~~)/ {
            indent = match($0, /[^ ]/) - 1
            rest   = substr($0, indent + 1)
            fchar  = substr(rest, 1, 1)
            flen   = fence_len(rest, fchar)
            info   = substr(rest, flen + 1)
            n += 1
            lang = info; sub(/ .*/, "", lang)
            if (lang == "") lang = "none"
            mode = "MISSING"
            if (match(info, /doctest=[^ ]+/))
                mode = substr(info, RSTART + 8, RLENGTH - 8)
            file = sprintf("%s/block_%03d", out, n)
            printf "" > file
            printf "%d\t%s\t%s\t%d\n", n, lang, mode, NR >> manifest
            inb = 1
            next
        }

        # Inside a block: any fence-looking line must be a well-formed close.
        inb == 1 && /^ *(```|~~~)/ {
            ci    = match($0, /[^ ]/) - 1
            crest = substr($0, ci + 1)
            cchar = substr(crest, 1, 1)
            clen  = fence_len(crest, cchar)
            trail = substr(crest, clen + 1)
            if (cchar == fchar && clen >= flen && ci <= indent && trail ~ /^[[:space:]]*$/) {
                inb = 0
                close(file)
                next
            }
            if (cchar == fchar && clen >= flen && ci <= indent) {
                fail("line " NR ": closing fence has trailing text: " $0)
            } else {
                fail("line " NR ": unexpected fence inside a block: " $0)
            }
            inb = 0
            close(file)
            next
        }

        inb == 1 {
            body = $0
            if (indent > 0 && substr(body, 1, indent) ~ /^ +$/)
                body = substr(body, indent + 1)
            else if (indent > 0 && body ~ /^ +$/)
                body = ""
            print body >> file
        }

        END {
            if (inb == 1) fail("unterminated fenced block opened before EOF")
            if (err) exit 3
        }
    ' "${GUIDE}"
}

# --- generic checkers -------------------------------------------------------
# Convention: return 0 pass, 1 fail, 2 checker unavailable.

check_parses() {
    local file="$1"
    bash -n "${file}" 2>>"${WORK}/errors" || return 1
}

# `bash -n` alone is close to a rubber stamp: it passes on an empty file, on
# arbitrary prose, and on `rm -rf /`. For illustrative snippets, also require
# the block to actually invoke a tool the guide claims to use.
check_syntax() {
    local file="$1"
    check_parses "${file}" || return 1
    if ! grep -qE "^[[:space:]]*(exec[[:space:]]+)?(${KNOWN_COMMANDS})[[:space:]]" "${file}"; then
        printf 'block invokes none of the expected commands (%s)\n' \
            "${KNOWN_COMMANDS//|/, }" >>"${WORK}/errors"
        return 1
    fi
}

check_shellcheck() {
    local file="$1"
    "${HAVE_SHELLCHECK}" || return 2
    # Any nonzero shellcheck exit is a real failure: 1 = issues found,
    # 2 = file could not be processed, 3/4 = bad invocation. None are "skip".
    shellcheck --shell=bash "${file}" >>"${WORK}/errors" 2>&1 || return 1
}

check_sshconfig() {
    local file="$1"
    # ssh_config has no inline comments: a trailing "# ..." is swallowed as
    # extra arguments and `ssh -G` does NOT reject it. Enforce statically.
    local line
    while IFS= read -r line; do
        [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ "${line}" == *'#'* ]]; then
            printf 'inline comment in ssh_config line: %s\n' "${line}" \
                >>"${WORK}/errors"
            return 1
        fi
    done < "${file}"
    "${HAVE_SSH}" || return 2
    ssh -G -F "${file}" prov-i-0abc123 >/dev/null 2>>"${WORK}/errors" || return 1
}

check_toml() {
    local file="$1"
    "${HAVE_PYTHON_TOML}" || return 2
    python3 -c 'import sys, tomllib; tomllib.load(open(sys.argv[1], "rb"))' \
        "${file}" 2>>"${WORK}/errors" || return 1
}

# Every non-comment line must be KEY=op://vault/item[/section]/field, so a
# malformed reference (op:/Prod/..., missing field) cannot ship green.
check_envtpl() {
    local file="$1" line found=0
    while IFS= read -r line; do
        [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ ! "${line}" =~ ^[A-Za-z_][A-Za-z0-9_]*=op://[^/]+/[^/]+(/[^/]+)+$ ]]; then
            printf 'not a KEY=op://vault/item/field reference: %s\n' "${line}" \
                >>"${WORK}/errors"
            return 1
        fi
        found=1
    done < "${file}"
    if ((found == 0)); then
        printf 'env template contains no secret references\n' >>"${WORK}/errors"
        return 1
    fi
}

# Shared by ini and unit: section headers, key=value lines, backslash
# continuations, and NO inline comments (systemd treats a trailing "# ..."
# as part of the value).
check_ini_static() {
    local file="$1"
    local line continued=0
    while IFS= read -r line; do
        if ((continued == 1)); then
            [[ "${line}" == *"\\" ]] || continued=0
            continue
        fi
        [[ -z "${line}" ]] && continue
        [[ "${line}" =~ ^[[:space:]]*[#\;] ]] && continue
        if [[ "${line}" =~ ^\[[A-Za-z][A-Za-z0-9]*\]$ ]]; then
            continue
        fi
        if [[ "${line}" =~ ^[A-Za-z][A-Za-z0-9]*= ]]; then
            local value="${line#*=}"
            if [[ "${value}" =~ [[:space:]]\#[[:space:]] ]]; then
                printf 'inline comment in value: %s\n' "${line}" >>"${WORK}/errors"
                return 1
            fi
            [[ "${line}" == *"\\" ]] && continued=1
            continue
        fi
        printf 'not a section/key=value line: %s\n' "${line}" >>"${WORK}/errors"
        return 1
    done < "${file}"
}

check_unit() {
    local file="$1"
    check_ini_static "${file}" || return 1
    "${HAVE_SYSTEMD_ANALYZE}" || return 0
    local unit_dir="${WORK}/units"
    mkdir -p "${unit_dir}"
    cp "${file}" "${unit_dir}/doctest.service"
    systemd-analyze verify "${unit_dir}/doctest.service" 2>>"${WORK}/errors" || return 1
}

# --- run:<name> scenarios ---------------------------------------------------

# The stub `op` emits DOCTEST_SECRET, a per-run nonce. Asserting that exact
# nonce crosses the wire proves provenance: the value came from `op`, not from
# a literal hardcoded in the block.
DOCTEST_SECRET=''

new_secret() {
    # `tr < /dev/urandom | head -c 32` would SIGPIPE tr, and pipefail turns
    # that into a fatal 141. Read a bounded number of bytes instead.
    LC_ALL=C od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
}

run_block() {
    local file="$1" logdir="$2" workdir="$3" fail_op="${4:-0}"
    mkdir -p "${logdir}" "${workdir}"
    (
        cd "${workdir}"
        env PATH="${STUBS_DIR}:${PATH}" \
            DOCTEST_LOG="${logdir}" \
            DOCTEST_SECRET="${DOCTEST_SECRET}" \
            OP_STUB_FAIL="${fail_op}" \
            SECRETSPEC_STUB_FAIL="${fail_op}" \
            bash "${file}" </dev/null >>"${WORK}/errors" 2>&1
    )
}

assert_single_ssh() {
    local logdir="$1" tag="$2" count
    count="$(wc -l < "${logdir}/ssh.calls" | tr -d ' ')"
    if [[ "${count}" != '1' ]]; then
        printf '%s: expected exactly 1 ssh invocation, saw %s\n' "${tag}" "${count}" \
            >>"${WORK}/errors"
        return 1
    fi
}

ssh_argv_value_after() {
    local logdir="$1" flag="$2"
    awk -v flag="${flag}" 'prev == flag { print; exit } { prev = $0 }' \
        "${logdir}/ssh.argv"
}

# Phase 1.3: the ephemeral EIC keypair must exist when `aws` runs (the aws stub
# enforces that), be the key ssh uses, and be shredded by the trap.
scenario_eic() {
    local file="$1" logdir="${WORK}/log_eic" workdir="${WORK}/run_eic"
    run_block "${file}" "${logdir}" "${workdir}" || return 1
    assert_single_ssh "${logdir}" 'eic' || return 1

    local keyfile
    keyfile="$(ssh_argv_value_after "${logdir}" '-i')"
    if [[ -z "${keyfile}" ]]; then
        printf 'eic: ssh was not invoked with -i <keyfile>\n' >>"${WORK}/errors"
        return 1
    fi
    # The aws stub already proved this path held a real ed25519 pubkey, so a
    # bogus path cannot reach here and pass vacuously.
    if [[ -e "${keyfile}" || -e "${keyfile}.pub" ]]; then
        printf 'eic: ephemeral key left behind at %s\n' "${keyfile}" >>"${WORK}/errors"
        return 1
    fi
}

# Phase 3 Track A: exactly the guide's own templated keys cross on stdin; the
# secret never reaches argv; a failed `op inject` means ssh never runs.
scenario_stream() {
    local file="$1" logdir="${WORK}/log_stream" workdir="${WORK}/run_stream"
    mkdir -p "${workdir}"
    # Use the guide's real .env.tpl block, not a fabricated copy, so the
    # template the reader pastes is the template under test.
    [[ -s "${WORK}/env.tpl" ]] || {
        printf 'stream: guide has no doctest=envtpl block to source .env.tpl from\n' \
            >>"${WORK}/errors"
        return 1
    }
    cp "${WORK}/env.tpl" "${workdir}/.env.tpl"

    run_block "${file}" "${logdir}" "${workdir}" || return 1
    assert_single_ssh "${logdir}" 'stream' || return 1

    local expected actual
    expected="$(sed -E "s#op://[^[:space:]]+#${DOCTEST_SECRET}#" "${WORK}/env.tpl")"$'\n'
    actual="$(cat "${logdir}/ssh.stdin"; printf x)"
    actual="${actual%x}"
    if [[ "${actual}" != "${expected}" ]]; then
        # Report shape only. Key names are not secret; values are.
        printf 'stream: stdin mismatch — expected keys [%s], got %d line(s) with keys [%s]\n' \
            "$(cut -d= -f1 < "${WORK}/env.tpl" | paste -sd, -)" \
            "$(printf '%s' "${actual}" | grep -c '' || true)" \
            "$(printf '%s' "${actual}" | cut -d= -f1 | paste -sd, -)" \
            >>"${WORK}/errors"
        return 1
    fi
    if grep -q "${DOCTEST_SECRET}" "${logdir}/ssh.argv"; then
        printf 'stream: secret leaked into ssh argv\n' >>"${WORK}/errors"
        return 1
    fi
    if ! grep -q 'systemd-run' "${logdir}/ssh.argv"; then
        printf 'stream: remote command does not use systemd-run\n' >>"${WORK}/errors"
        return 1
    fi

    local faillog="${WORK}/log_stream_fail"
    if run_block "${file}" "${faillog}" "${WORK}/run_stream_fail" 1; then
        printf 'stream: block succeeded despite op failure\n' >>"${WORK}/errors"
        return 1
    fi
    if [[ -e "${faillog}/ssh.argv" ]]; then
        printf 'stream: ssh ran even though op inject failed\n' >>"${WORK}/errors"
        return 1
    fi
}

# Phase 4.1 / Appendix A.1. $2 is the required --with-key= value. A block
# claiming one key mode while using another is a security-relevant defect:
# `host` and `tpm2` have different at-rest properties, and `host+tpm2` (the
# systemd default) is neither — so the match must be token-anchored.
seal_assertions() {
    local file="$1" key_mode="$2" tag="$3"
    local logdir="${WORK}/log_${tag}" workdir="${WORK}/run_${tag}"
    run_block "${file}" "${logdir}" "${workdir}" || return 1
    assert_single_ssh "${logdir}" "${tag}" || return 1

    local actual
    actual="$(cat "${logdir}/ssh.stdin"; printf x)"
    actual="${actual%x}"
    if [[ "${actual}" != "${DOCTEST_SECRET}" ]]; then
        printf '%s: stdin did not carry exactly the op-provided secret (%d bytes received)\n' \
            "${tag}" "${#actual}" >>"${WORK}/errors"
        return 1
    fi
    if grep -q "${DOCTEST_SECRET}" "${logdir}/ssh.argv"; then
        printf '%s: secret leaked into ssh argv\n' "${tag}" >>"${WORK}/errors"
        return 1
    fi
    if ! grep -q 'systemd-creds encrypt' "${logdir}/ssh.argv"; then
        printf '%s: remote command does not seal via systemd-creds\n' "${tag}" \
            >>"${WORK}/errors"
        return 1
    fi
    # Anchored: --with-key=host must not match --with-key=host+tpm2.
    if ! grep -qE -- "--with-key=${key_mode}([^+[:alnum:]]|$)" "${logdir}/ssh.argv"; then
        printf '%s: expected --with-key=%s (exactly) in the remote command\n' \
            "${tag}" "${key_mode}" >>"${WORK}/errors"
        return 1
    fi

    local faillog="${WORK}/log_${tag}_fail"
    if run_block "${file}" "${faillog}" "${WORK}/run_${tag}_fail" 1; then
        printf '%s: block succeeded despite op failure\n' "${tag}" >>"${WORK}/errors"
        return 1
    fi
    if [[ -e "${faillog}/ssh.argv" ]]; then
        printf '%s: ssh ran even though op read failed\n' "${tag}" >>"${WORK}/errors"
        return 1
    fi
}

scenario_seal()      { seal_assertions "$1" 'tpm2' 'seal'; }
scenario_seal_host() { seal_assertions "$1" 'host' 'sealhost'; }

# Appendix B: SecretSpec as the declaration layer. Same invariants as
# run:stream — the resolved values reach stdin only, never argv or the
# environment, and a failed resolve aborts before ssh runs. This is what stops
# `secretspec run` (env injection) from creeping across the SSH boundary.
scenario_secretspec() {
    local file="$1" logdir="${WORK}/log_ss" workdir="${WORK}/run_ss"
    run_block "${file}" "${logdir}" "${workdir}" || return 1
    assert_single_ssh "${logdir}" 'secretspec' || return 1

    local expected actual
    expected="$(printf 'DB_PASSWORD=%s\nAPI_KEY=%s\n' "${DOCTEST_SECRET}" "${DOCTEST_SECRET}")"
    actual="$(cat "${logdir}/ssh.stdin"; printf x)"
    actual="${actual%x}"
    if [[ "${actual}" != "${expected}"$'\n' && "${actual}" != "${expected}" ]]; then
        # Report shape only — key names are not secret, values are. If the keys
        # match, the values did not come from secretspec (provenance failure).
        local seen
        seen="$(printf '%s' "${actual}" | cut -d= -f1 | paste -sd, -)"
        if [[ "${seen}" == 'DB_PASSWORD,API_KEY' ]]; then
            printf 'secretspec: keys correct but values are not the ones secretspec returned (hardcoded?)\n' \
                >>"${WORK}/errors"
        else
            printf 'secretspec: stdin mismatch — expected keys [DB_PASSWORD,API_KEY], got [%s]\n' \
                "${seen}" >>"${WORK}/errors"
        fi
        return 1
    fi
    if grep -q "${DOCTEST_SECRET}" "${logdir}/ssh.argv"; then
        printf 'secretspec: secret leaked into ssh argv\n' >>"${WORK}/errors"
        return 1
    fi
    # "secretspec run" would inject into the environment; the guide must use
    # "secretspec get", whose value goes to stdout.
    if grep -q '^run ' "${logdir}/secretspec.argv"; then
        printf 'secretspec: block used secretspec run (env injection) across the SSH boundary\n' \
            >>"${WORK}/errors"
        return 1
    fi
    if ! grep -q '^get ' "${logdir}/secretspec.argv"; then
        printf 'secretspec: block never called secretspec get\n' >>"${WORK}/errors"
        return 1
    fi

    local faillog="${WORK}/log_ss_fail"
    if run_block "${file}" "${faillog}" "${WORK}/run_ss_fail" 1; then
        printf 'secretspec: block succeeded despite a failed secret resolve\n' \
            >>"${WORK}/errors"
        return 1
    fi
    if [[ -e "${faillog}/ssh.argv" ]]; then
        printf 'secretspec: ssh ran even though secretspec failed\n' >>"${WORK}/errors"
        return 1
    fi
}

run_scenario() {
    local name="$1" file="$2"
    case "${name}" in
        eic)        scenario_eic "${file}" ;;
        stream)     scenario_stream "${file}" ;;
        seal)       scenario_seal "${file}" ;;
        seal-host)  scenario_seal_host "${file}" ;;
        secretspec) scenario_secretspec "${file}" ;;
        *)
            printf 'unknown run scenario: %s\n' "${name}" >>"${WORK}/errors"
            return 1
            ;;
    esac
}

# --- dispatch ---------------------------------------------------------------

dispatch() {
    local n="$1" lang="$2" mode="$3" line="$4"
    local file id rc=0 lint_rc=0
    file="$(printf '%s/block_%03d' "${WORK}" "${n}")"
    id="${n}:${line}"

    : > "${WORK}/errors"

    case "${mode}" in
        MISSING)
            report FAIL "${id}" "${lang}" 'fenced block has no doctest= annotation'
            return 0
            ;;
        syntax)    check_syntax    "${file}" || rc=$? ;;
        sshconfig) check_sshconfig "${file}" || rc=$? ;;
        toml)      check_toml      "${file}" || rc=$? ;;
        envtpl)    check_envtpl    "${file}" || rc=$? ;;
        ini)       check_ini_static "${file}" || rc=$? ;;
        unit)      check_unit      "${file}" || rc=$? ;;
        script)
            # A complete script: shellcheck is the real check, so no
            # known-command heuristic here.
            if check_parses "${file}"; then
                check_shellcheck "${file}" || rc=$?
            else
                rc=1
            fi
            ;;
        run:*)
            if ! check_parses "${file}"; then
                rc=1
            else
                check_shellcheck "${file}" || lint_rc=$?
                # lint_rc=1 is a real lint failure. lint_rc=2 means shellcheck
                # is absent, which must NEVER skip the run assertions — they
                # are the security-relevant part of this mode.
                if ((lint_rc == 1)); then
                    rc=1
                fi
            fi
            if ((rc == 0)); then
                run_scenario "${mode#run:}" "${file}" || rc=1
            fi
            ;;
        *)
            report FAIL "${id}" "${mode}" 'unknown doctest mode'
            return 0
            ;;
    esac

    if ((rc == 0)); then
        report PASS "${id}" "${mode}"
    elif ((rc == 2)); then
        report SKIP "${id}" "${mode}" 'checker unavailable on this host'
    else
        report FAIL "${id}" "${mode}" "$(tr '\n' ' ' < "${WORK}/errors")"
    fi
}

# scenario_stream needs the guide's .env.tpl before its own block is dispatched,
# so stage it up front.
stage_env_tpl() {
    local n lang mode line
    while IFS=$'\t' read -r n lang mode line; do
        if [[ "${mode}" == 'envtpl' ]]; then
            cp "$(printf '%s/block_%03d' "${WORK}" "${n}")" "${WORK}/env.tpl"
            # Strip comments so the template is exactly the KEY=ref lines.
            grep -vE '^[[:space:]]*(#|$)' "${WORK}/env.tpl" > "${WORK}/env.tpl.tmp"
            mv "${WORK}/env.tpl.tmp" "${WORK}/env.tpl"
            return 0
        fi
    done < "${WORK}/manifest"
    return 0
}

main() {
    [[ -r "${GUIDE}" ]] || die "guide not found: ${GUIDE}"
    [[ -d "${STUBS_DIR}" ]] || die "stubs directory missing: ${STUBS_DIR}"

    probe_tools
    DOCTEST_SECRET="$(new_secret)"
    readonly DOCTEST_SECRET
    [[ ${#DOCTEST_SECRET} -eq 32 ]] || die 'could not generate a test secret'

    if ! extract_blocks; then
        printf 'FATAL: the guide contains markdown this harness refuses to guess at:\n' >&2
        cat "${WORK}/extract_errors" >&2
        exit 1
    fi
    [[ -s "${WORK}/manifest" ]] || die 'no fenced code blocks found in guide'

    stage_env_tpl

    local n lang mode line
    while IFS=$'\t' read -r n lang mode line; do
        dispatch "${n}" "${lang}" "${mode}" "${line}"
    done < "${WORK}/manifest"

    printf '\n%d passed, %d failed, %d skipped (of %d blocks)\n' \
        "${PASS_COUNT}" "${FAIL_COUNT}" "${SKIP_COUNT}" \
        "$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))" >&2

    ((FAIL_COUNT == 0))
}

main "$@"
