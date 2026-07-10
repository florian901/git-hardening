#!/usr/bin/env bash
# run-instance-tests.sh — ship remote-tests.sh to a NitroTPM instance over SSM,
# run it as root, and stream back the result. No inbound ports, no SSH keys.
#
#   AWS_PROFILE=<p> ./run-instance-tests.sh --region us-east-2
#
# With no --instance-id it discovers the box tagged dev-harden:test=true that
# create-test-instance.sh stood up.
set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

readonly TAG_KEY='dev-harden:test'
readonly TAG_VALUE='true'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly REMOTE_SRC="${SCRIPT_DIR}/remote-tests.sh"
readonly REMOTE_PATH='/tmp/dev-harden-remote-tests.sh'

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
INSTANCE_ID=''

export AWS_PAGER=''

log()  { printf '==> %s\n' "$*" >&2; }
die()  { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

usage() {
    cat >&2 <<'EOF'
Usage:
  run-instance-tests.sh [--region R] [--instance-id i-...]

Ships remote-tests.sh to the NitroTPM test instance over SSM and runs it as root.
Discovers the instance tagged dev-harden:test=true when --instance-id is omitted.
EOF
}

parse_args() {
    while (($# > 0)); do
        case "$1" in
            --region)      [[ -n "${2:-}" ]] || die '--region needs a value'; REGION="$2"; shift 2 ;;
            --instance-id) [[ -n "${2:-}" ]] || die '--instance-id needs a value'; INSTANCE_ID="$2"; shift 2 ;;
            -h|--help)     usage; exit 0 ;;
            *)             usage; die "unknown argument: $1" ;;
        esac
    done
    [[ -n "${REGION}" ]] || die 'no region (pass --region or set AWS_REGION/AWS_DEFAULT_REGION)'
    [[ -f "${REMOTE_SRC}" ]] || die "cannot find ${REMOTE_SRC}"
}

discover_instance() {
    [[ -n "${INSTANCE_ID}" ]] && return 0
    log "discovering instance tagged ${TAG_KEY}=${TAG_VALUE}"
    INSTANCE_ID="$(aws ec2 describe-instances --region "${REGION}" \
        --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
                  'Name=instance-state-name,Values=running' \
        --query 'Reservations[].Instances[].InstanceId | [0]' --output text)"
    [[ -n "${INSTANCE_ID}" && "${INSTANCE_ID}" != 'None' ]] \
        || die "no running instance tagged ${TAG_KEY}=${TAG_VALUE} in ${REGION}"
    log "instance ${INSTANCE_ID}"
}

# SSM caps a single command parameter at ~2.5 KB, well under the script size, so
# base64 the source, land it in a heredoc on the box, decode, then execute.
run_over_ssm() {
    local b64
    b64="$(base64 < "${REMOTE_SRC}" | tr -d '\n')"

    local commands
    commands="$(cat <<EOF
set -e
printf '%s' '${b64}' | base64 -d > '${REMOTE_PATH}'
chmod 700 '${REMOTE_PATH}'
sudo bash '${REMOTE_PATH}'
rc=\$?
rm -f '${REMOTE_PATH}'
exit \$rc
EOF
)"

    # The whole script rides in one parameter; build the JSON with a tool, never
    # by hand, so quotes/newlines in the payload can't break the document.
    local params
    params="$(REMOTE_CMDS="${commands}" python3 -c '
import json, os
print(json.dumps({"commands": [os.environ["REMOTE_CMDS"]]}))')"

    log 'sending remote-tests.sh over SSM (RunShellScript)'
    local cmd_id
    cmd_id="$(aws ssm send-command --region "${REGION}" \
        --instance-ids "${INSTANCE_ID}" \
        --document-name 'AWS-RunShellScript' \
        --parameters "${params}" \
        --query 'Command.CommandId' --output text)"
    log "command ${cmd_id}; waiting for completion"

    # `wait command-executed` returns as soon as the command reaches ANY terminal
    # state, but get-command-invocation is separately eventually consistent, so a
    # field read straight after the wait can still race and show a non-terminal
    # Status. Poll get-command-invocation ourselves until Status is terminal, and
    # read all three fields from ONE response so they can't disagree.
    aws ssm wait command-executed \
        --command-id "${cmd_id}" --instance-id "${INSTANCE_ID}" \
        --region "${REGION}" 2>/dev/null || true

    local status='' stdout='' stderr='' payload='' attempt=0
    while ((attempt < 30)); do
        payload="$(aws ssm get-command-invocation --region "${REGION}" \
            --command-id "${cmd_id}" --instance-id "${INSTANCE_ID}" \
            --query '[Status,StandardOutputContent,StandardErrorContent]' \
            --output json 2>/dev/null || true)"
        if [[ -n "${payload}" ]]; then
            status="$(PAYLOAD="${payload}" python3 -c '
import json, os
v = json.loads(os.environ["PAYLOAD"])
print(v[0] or "")' 2>/dev/null || true)"
            # Terminal states per the SSM API.
            case "${status}" in
                Success|Failed|Cancelled|TimedOut|Undeliverable|Terminated) break ;;
            esac
        fi
        attempt=$((attempt + 1))
        sleep 2
    done

    if [[ -n "${payload}" ]]; then
        stdout="$(PAYLOAD="${payload}" python3 -c '
import json, os
v = json.loads(os.environ["PAYLOAD"])
print(v[1] or "", end="")' 2>/dev/null || true)"
        stderr="$(PAYLOAD="${payload}" python3 -c '
import json, os
v = json.loads(os.environ["PAYLOAD"])
print(v[2] or "", end="")' 2>/dev/null || true)"
    fi

    printf '\n%s\n' "${stdout}"
    [[ -n "${stderr}" ]] && printf -- '--- stderr ---\n%s\n' "${stderr}" >&2

    log "SSM status: ${status:-<unknown>}"
    # Success == remote-tests.sh exited 0 == every check passed. Any other
    # terminal state means a real failure to propagate.
    if [[ "${status}" == 'Success' ]]; then
        return 0
    fi
    die "instance tests did not pass (SSM status ${status:-unknown})"
}

main() {
    parse_args "$@"
    discover_instance
    run_over_ssm
}

main "$@"
