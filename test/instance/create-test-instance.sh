#!/usr/bin/env bash
# create-test-instance.sh — stand up (or tear down) a disposable NitroTPM EC2
# instance for the guide's instance-level test suite.
#
# There are no preconfigured Linux NitroTPM AMIs; TPM support can only be set
# when an AMI is REGISTERED, never afterwards. And you cannot copy the snapshot
# behind someone else's AMI — only snapshots you own or that are shared with
# you. So the supported route is:
#   1. resolve the latest AL2023 AMI and verify it is UEFI-capable + ENA
#   2. copy-image it into this account, encrypted  (this gives us a snapshot we own)
#   3. register a NEW AMI from that snapshot with --tpm-support v2.0
#   4. launch it with an SSM instance profile, IMDSv2 required, no inbound ports
#   5. install tpm2-tss and verify a real --with-key=tpm2 seal+unseal over SSM
#      (has-tpm2 alone lies: it passes on stock AL2023 while sealing still fails)
#
# Auth: uses your ambient AWS credential chain. For IAM Identity Center (SSO):
#   aws sso login --profile <p>
#   AWS_PROFILE=<p> ./create-test-instance.sh --create --region us-east-2
# The 1Password `op plugin` path only works with static access keys; it cannot
# model SSO, so this script does not assume it.
#
# Docs:
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-support-on-ami.html
#   https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/copy-ami-permissions.html
set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

readonly TAG_KEY='dev-harden:test'
readonly TAG_VALUE='true'
readonly STACK_NAME='dev-harden-nitrotpm-test'
readonly SSM_AMI_PARAM='/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
readonly ROLE_NAME='dev-harden-test-ssm-role'
readonly PROFILE_NAME='dev-harden-test-ssm-profile'
readonly DENY_POLICY_NAME='dev-harden-test-deny-parameter-store'

# T3/M5/C5+ support NitroTPM. Keep it small; this box only runs tests.
INSTANCE_TYPE="${INSTANCE_TYPE:-t3.small}"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
EXPECTED_ACCOUNT=''
ASSUME_YES=false
ALLOW_UNVERIFIED=false
ACCOUNT_ID=''

export AWS_PAGER=''

log()  { printf '==> %s\n' "$*" >&2; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

usage() {
    cat >&2 <<'EOF'
Usage:
  create-test-instance.sh --create  [--region R] [--instance-type T] [--account ID]
                                    [--allow-unverified] [--yes]
  create-test-instance.sh --destroy [--region R] [--account ID] [--yes]
  create-test-instance.sh --status  [--region R]

Creates a disposable NitroTPM instance tagged dev-harden:test=true.
No inbound ports are opened; access is via SSM Session Manager / EC2 Instance
Connect, exactly as the guide prescribes.

  --account ID        Refuse to act unless the caller is in this AWS account.
  --yes               Skip the destroy confirmation prompt.
  --allow-unverified  Do not fail --create when the NitroTPM check is inconclusive.

Auth: uses the ambient AWS credential chain (AWS_PROFILE, SSO, env vars).
  IAM Identity Center:  aws sso login --profile <p> && AWS_PROFILE=<p> ...

Cost: t3.small + gp3 root ~= $0.02/hr, plus one encrypted snapshot.
Run --destroy when finished; it removes the instance, both AMIs, and the snapshot.
EOF
}

confirm() {
    local prompt="$1" reply=''
    "${ASSUME_YES}" && return 0
    printf '%s [type: yes] ' "${prompt}" >&2
    read -r reply || true
    [[ "${reply}" == 'yes' ]]
}

# --- preflight --------------------------------------------------------------

preflight() {
    command -v aws >/dev/null || die 'aws CLI not found'
    command -v jq  >/dev/null || die 'jq not found'

    [[ -n "${REGION}" ]] \
        || die 'no region: pass --region, or set AWS_REGION / AWS_DEFAULT_REGION'
    # Export so every later `aws` call (including `aws iam`, which is global but
    # still needs a region to resolve an endpoint) sees it. This also removes
    # the need to thread --region through every invocation.
    export AWS_DEFAULT_REGION="${REGION}"

    local caller_arn
    if ! caller_arn="$(aws sts get-caller-identity --query Arn --output text 2>&1)"; then
        printf 'FATAL: cannot authenticate to AWS in region %s\n' "${REGION}" >&2
        printf '  aws said: %s\n' "${caller_arn}" >&2
        printf '  If you use IAM Identity Center (SSO):\n' >&2
        printf '    aws sso login --profile <profile>\n' >&2
        printf '    AWS_PROFILE=<profile> %s --create --region %s\n' "$0" "${REGION}" >&2
        printf '  If you use static access keys stored in 1Password:\n' >&2
        printf '    op plugin run -- aws sts get-caller-identity\n' >&2
        exit 1
    fi

    ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
    readonly ACCOUNT_ID

    if [[ -n "${EXPECTED_ACCOUNT}" && "${ACCOUNT_ID}" != "${EXPECTED_ACCOUNT}" ]]; then
        die "caller is in account ${ACCOUNT_ID}, expected ${EXPECTED_ACCOUNT}"
    fi

    log "caller:  ${caller_arn}"
    log "account: ${ACCOUNT_ID}"
    log "region:  ${REGION}"
}

# --- IAM: SSM core PLUS an inline Deny on Parameter Store -------------------
#
# AmazonSSMManagedInstanceCore is NOT a minimal role: its first statement grants
# ssm:GetParameter and ssm:GetParameters on "Resource": "*", so root on the
# instance could read every Parameter Store value in the account, SecureStrings
# included. The managed policy is still the only documented way to get both
# Session Manager and send-command working, so we attach it and Deny the rest.
#   https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonSSMManagedInstanceCore.html

readonly DENY_POLICY_JSON='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NoParameterStoreReads",
      "Effect": "Deny",
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ssm:GetParameterHistory",
        "ssm:DescribeParameters"
      ],
      "Resource": "*"
    }
  ]
}'

ensure_instance_profile() {
    if aws iam get-instance-profile --instance-profile-name "${PROFILE_NAME}" \
        >/dev/null 2>&1; then
        log "instance profile ${PROFILE_NAME} already exists"
        return 0
    fi

    log "creating IAM role ${ROLE_NAME}"
    local trust
    trust='{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    trust+='"Principal":{"Service":"ec2.amazonaws.com"},'
    trust+='"Action":"sts:AssumeRole"}]}'

    aws iam create-role \
        --role-name "${ROLE_NAME}" \
        --assume-role-policy-document "${trust}" \
        --tags "Key=${TAG_KEY},Value=${TAG_VALUE}" >/dev/null

    aws iam attach-role-policy --role-name "${ROLE_NAME}" \
        --policy-arn 'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'

    log 'attaching inline Deny on Parameter Store reads'
    aws iam put-role-policy --role-name "${ROLE_NAME}" \
        --policy-name "${DENY_POLICY_NAME}" \
        --policy-document "${DENY_POLICY_JSON}"

    aws iam create-instance-profile --instance-profile-name "${PROFILE_NAME}" \
        --tags "Key=${TAG_KEY},Value=${TAG_VALUE}" >/dev/null
    aws iam add-role-to-instance-profile \
        --instance-profile-name "${PROFILE_NAME}" --role-name "${ROLE_NAME}"

    aws iam wait instance-profile-exists --instance-profile-name "${PROFILE_NAME}"
    # The waiter proves IAM-side existence only. Propagation into EC2's control
    # plane is separate and AWS documents no sufficient wait, so run-instances
    # retries below rather than sleeping a magic number here.
}

# --- AMI: resolve, verify, copy-image, register with TPM ---------------------

resolve_source_ami() {
    local ami_id
    ami_id="$(aws ssm get-parameter --name "${SSM_AMI_PARAM}" \
        --query 'Parameter.Value' --output text)"
    [[ "${ami_id}" == ami-* ]] || die "could not resolve AMI from ${SSM_AMI_PARAM}"
    printf '%s' "${ami_id}"
}

tag_resource() {
    local resource_id="$1" name="$2"
    aws ec2 create-tags --resources "${resource_id}" \
        --tags "Key=${TAG_KEY},Value=${TAG_VALUE}" "Key=Name,Value=${name}"
}

register_nitrotpm_ami() {
    local src_ami="$1"
    local desc count boot_mode ena arch root_dev

    desc="$(aws ec2 describe-images --image-ids "${src_ami}" --output json)"
    count="$(jq -r '.Images | length' <<<"${desc}")"
    [[ "${count}" == '1' ]] || die "describe-images returned ${count} images for ${src_ami}"

    boot_mode="$(jq -r '.Images[0].BootMode // "legacy-bios"' <<<"${desc}")"
    ena="$(jq -r '.Images[0].EnaSupport // false' <<<"${desc}")"
    arch="$(jq -r '.Images[0].Architecture' <<<"${desc}")"
    root_dev="$(jq -r '.Images[0].RootDeviceName' <<<"${desc}")"

    # NitroTPM requires UEFI boot. Registering a legacy-bios image with
    # --boot-mode uefi yields an AMI that will not boot.
    case "${boot_mode}" in
        uefi|uefi-preferred) ;;
        *) die "source AMI ${src_ami} has BootMode=${boot_mode}; UEFI required for NitroTPM" ;;
    esac
    # T3 is a Nitro type and requires ENA. Registering without it produces an
    # AMI that boots but never networks — which would surface five minutes later
    # as "SSM agent never came Online".
    [[ "${ena}" == 'true' ]] \
        || die "source AMI ${src_ami} lacks ENA support; ${INSTANCE_TYPE} requires it"

    log "source AMI ${src_ami} (${arch}, BootMode=${boot_mode}, ENA=${ena})"

    # We cannot copy-snapshot Amazon's snapshot: you may only copy snapshots you
    # own or that are shared with you. copy-image DOES grant permission to copy
    # an AMI's backing snapshots, and gives us an encrypted snapshot we own.
    log 'copy-image into this account (encrypted) — takes a few minutes'
    local copy_ami
    copy_ami="$(aws ec2 copy-image \
        --source-region "${REGION}" \
        --source-image-id "${src_ami}" \
        --name "${STACK_NAME}-copy-$(date +%Y%m%d%H%M%S)" \
        --description "${STACK_NAME} intermediate copy" \
        --encrypted \
        --query ImageId --output text)"
    # Tag immediately: an untagged intermediate would be invisible to --destroy.
    tag_resource "${copy_ami}" "${STACK_NAME}-copy"
    aws ec2 wait image-available --image-ids "${copy_ami}"

    local snap
    snap="$(aws ec2 describe-images --image-ids "${copy_ami}" --owners self \
        --query "Images[0].BlockDeviceMappings[?DeviceName=='${root_dev}'].Ebs.SnapshotId | [0]" \
        --output text)"
    [[ "${snap}" == snap-* ]] || die "could not find root snapshot of ${copy_ami}"
    tag_resource "${snap}" "${STACK_NAME}-root"
    log "owned encrypted snapshot: ${snap}"

    # register-image has NO --tag-specifications (verified against aws-cli
    # 2.11.6); tag it in a follow-up call.
    log 'registering AMI with --tpm-support v2.0 --boot-mode uefi'
    local ami_id
    ami_id="$(aws ec2 register-image \
        --name "${STACK_NAME}-$(date +%Y%m%d%H%M%S)" \
        --description 'Disposable NitroTPM AMI for dev-harden guide tests' \
        --architecture "${arch}" \
        --root-device-name "${root_dev}" \
        --block-device-mappings \
          "DeviceName=${root_dev},Ebs={SnapshotId=${snap},VolumeType=gp3,DeleteOnTermination=true}" \
        --boot-mode uefi \
        --tpm-support v2.0 \
        --imds-support v2.0 \
        --ena-support \
        --query ImageId --output text)"
    tag_resource "${ami_id}" "${STACK_NAME}"

    # The intermediate has served its purpose; its snapshot lives on in our AMI.
    # Deregistering an AMI does not delete snapshots.
    aws ec2 deregister-image --image-id "${copy_ami}"
    log "deregistered intermediate ${copy_ami}"

    local verify
    verify="$(aws ec2 describe-images --image-ids "${ami_id}" --owners self \
        --query 'Images[0].[BootMode,TpmSupport]' --output text)"
    [[ "${verify}" == $'uefi\tv2.0' ]] \
        || die "registered AMI ${ami_id} has BootMode/TpmSupport = ${verify}"
    log "registered ${ami_id} (BootMode=uefi, TpmSupport=v2.0)"

    printf '%s' "${ami_id}"
}

# --- launch ------------------------------------------------------------------

launch_instance() {
    local ami_id="$1"
    log "launching ${INSTANCE_TYPE} from ${ami_id}"

    # No --security-group-ids: the default SG has no ingress and allows all
    # egress, which is what SSM needs.
    # No --associate-public-ip-address: a default subnet already sets
    # MapPublicIpOnLaunch, and the flag lowers into a NetworkInterfaces spec
    # that conflicts with instance-level security groups.
    # No --block-device-mappings: the root volume inherits encryption from the
    # AMI's encrypted snapshot.
    local instance_id='' attempt
    for ((attempt = 1; attempt <= 6; attempt++)); do
        if instance_id="$(aws ec2 run-instances \
            --image-id "${ami_id}" \
            --instance-type "${INSTANCE_TYPE}" \
            --iam-instance-profile "Name=${PROFILE_NAME}" \
            --metadata-options 'HttpTokens=required,HttpEndpoint=enabled' \
            --tag-specifications \
              "ResourceType=instance,Tags=[{Key=${TAG_KEY},Value=${TAG_VALUE}},{Key=Name,Value=${STACK_NAME}}]" \
            --query 'Instances[0].InstanceId' --output text 2>/dev/null)"; then
            break
        fi
        # A freshly created instance profile is not yet visible to EC2. AWS
        # documents no sufficient sleep; retry with backoff instead.
        log "run-instances rejected the instance profile (attempt ${attempt}/6); retrying"
        sleep $((attempt * 5))
        instance_id=''
    done
    [[ "${instance_id}" == i-* ]] || die 'run-instances failed; see AWS error above'

    log "waiting for ${instance_id} to run"
    aws ec2 wait instance-running --instance-ids "${instance_id}"
    log 'waiting for the SSM agent to register (~1 min)'

    local i online=''
    for ((i = 0; i < 30; i++)); do
        online="$(aws ssm describe-instance-information \
            --filters "Key=InstanceIds,Values=${instance_id}" \
            --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)"
        [[ "${online}" == 'Online' ]] && break
        sleep 10
    done
    [[ "${online}" == 'Online' ]] \
        || die "SSM agent never came Online for ${instance_id}; check egress and the instance role"

    printf '%s' "${instance_id}"
}

# `systemd-creds has-tpm2` prints "partial" (plus per-component yes/no lines)
# when only some of firmware/driver/system/kernel support TPM2, so a substring
# match on "yes" false-positives. The exit code is the authoritative signal:
# 0 = full support, otherwise a bitmask of what is missing.
verify_tpm() {
    local instance_id="$1"
    log 'verifying NitroTPM by an actual seal+unseal round-trip'

    # has-tpm2 is NOT sufficient: on stock AL2023 it reports every component
    # +yes while `systemd-creds encrypt --with-key=tpm2` still fails, because the
    # tpm2-tss runtime libraries systemd dlopen()s are not in the base image.
    # So install that prerequisite (as the guide now instructs) and then verify
    # by sealing and unsealing a throwaway credential. grep -qx keeps the probe
    # value off the wire.
    local probe='SEAL_ROUNDTRIP'
    local cmd_id
    # shellcheck disable=SC2016  # $$ and $n must expand on the instance, not here
    cmd_id="$(aws ssm send-command \
        --instance-ids "${instance_id}" \
        --document-name 'AWS-RunShellScript' \
        --parameters 'commands=["sudo dnf install -y tpm2-tss >/dev/null 2>&1 || true","systemd-creds has-tpm2 --quiet; printf \"has_tpm2_rc=%s\\n\" \"$?\"","test -c /dev/tpmrm0 && echo TPM_DEVICE_PRESENT || echo TPM_DEVICE_MISSING","n=tpmprobe-$$; printf %s '"${probe}"' | sudo systemd-creds encrypt --name=\"$n\" --with-key=tpm2 - \"/tmp/$n.cred\" 2>/dev/null && sudo systemd-creds decrypt --name=\"$n\" \"/tmp/$n.cred\" - 2>/dev/null | grep -qx '"${probe}"' && echo SEAL_ROUNDTRIP_OK || echo SEAL_ROUNDTRIP_FAIL; sudo rm -f \"/tmp/$n.cred\""]' \
        --query 'Command.CommandId' --output text)"

    # Run Command is eventually consistent: get-command-invocation can return
    # InvocationDoesNotExist if called too early, and Status may still be
    # InProgress with empty output. Wait for a terminal state instead.
    if ! aws ssm wait command-executed \
        --command-id "${cmd_id}" --instance-id "${instance_id}" 2>/dev/null; then
        warn "SSM command ${cmd_id} did not complete successfully"
    fi

    local out
    out="$(aws ssm get-command-invocation \
        --command-id "${cmd_id}" --instance-id "${instance_id}" \
        --query 'StandardOutputContent' --output text 2>/dev/null || true)"

    if [[ "${out}" == *'SEAL_ROUNDTRIP_OK'* ]]; then
        log 'NitroTPM sealing CONFIRMED (real --with-key=tpm2 seal+unseal round-trip)'
        return 0
    fi
    warn "NitroTPM sealing NOT confirmed. Command output: ${out:-<empty>}"
    return 1
}

# --- teardown ----------------------------------------------------------------
#
# Every describe here is scoped to resources we OWN. Without --owners self /
# --owner-ids self, describe-images and describe-snapshots return public
# resources too (their Tags are visible), so a public AMI carrying our tag would
# enter the delete loop.

destroy() {
    local instances images snapshots
    instances="$(aws ec2 describe-instances \
        --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
                  'Name=instance-state-name,Values=pending,running,stopping,stopped' \
        --query 'Reservations[].Instances[].InstanceId' --output text)"
    images="$(aws ec2 describe-images --owners self \
        --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
        --query 'Images[].ImageId' --output text)"
    snapshots="$(aws ec2 describe-snapshots --owner-ids self \
        --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
        --query 'Snapshots[].SnapshotId' --output text)"

    if [[ -z "${instances}${images}${snapshots}" ]]; then
        log 'nothing tagged for deletion'
        return 0
    fi

    printf '\nAbout to PERMANENTLY DELETE, in account %s / region %s:\n' \
        "${ACCOUNT_ID}" "${REGION}" >&2
    printf '  instances: %s\n' "${instances:-<none>}" >&2
    printf '  AMIs:      %s\n' "${images:-<none>}" >&2
    printf '  snapshots: %s\n' "${snapshots:-<none>}" >&2
    confirm 'Proceed?' || die 'aborted'

    if [[ -n "${instances}" ]]; then
        # shellcheck disable=SC2086  # intentional split on the tab-separated ID list
        aws ec2 terminate-instances --instance-ids ${instances} >/dev/null
        # shellcheck disable=SC2086
        aws ec2 wait instance-terminated --instance-ids ${instances}
        log "terminated: ${instances}"
    fi

    local image
    for image in ${images}; do
        # No `&& log` chain: a failing command in an && list does not trip
        # errexit, so teardown failures would be swallowed silently.
        aws ec2 deregister-image --image-id "${image}"
        log "deregistered ${image}"
    done

    local snap attempt
    for snap in ${snapshots}; do
        # deregister-image is not synchronous w.r.t. snapshot references, so a
        # delete right after can fail with InvalidSnapshot.InUse.
        for ((attempt = 1; attempt <= 5; attempt++)); do
            if aws ec2 delete-snapshot --snapshot-id "${snap}" 2>/dev/null; then
                log "deleted ${snap}"
                break
            fi
            ((attempt == 5)) && die "could not delete ${snap} after 5 attempts"
            sleep $((attempt * 5))
        done
    done

    log 'IAM role/profile left in place (reusable, zero cost). To remove:'
    log "  aws iam remove-role-from-instance-profile --instance-profile-name ${PROFILE_NAME} --role-name ${ROLE_NAME}"
    log "  aws iam delete-instance-profile --instance-profile-name ${PROFILE_NAME}"
    log "  aws iam delete-role-policy --role-name ${ROLE_NAME} --policy-name ${DENY_POLICY_NAME}"
    log "  aws iam detach-role-policy --role-name ${ROLE_NAME} --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    log "  aws iam delete-role --role-name ${ROLE_NAME}"
}

# status() writes results to stdout: it is data, not logging.
status() {
    printf '\nInstances:\n'
    aws ec2 describe-instances \
        --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
                  'Name=instance-state-name,Values=pending,running,stopping,stopped' \
        --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name,ImageId]' \
        --output table
    printf '\nAMIs:\n'
    aws ec2 describe-images --owners self \
        --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
        --query 'Images[].[ImageId,BootMode,TpmSupport,Name]' --output table
    printf '\nSnapshots:\n'
    aws ec2 describe-snapshots --owner-ids self \
        --filters "Name=tag:${TAG_KEY},Values=${TAG_VALUE}" \
        --query 'Snapshots[].[SnapshotId,VolumeSize,Encrypted]' --output table
}

create() {
    ensure_instance_profile
    local src_ami ami_id instance_id
    src_ami="$(resolve_source_ami)"
    ami_id="$(register_nitrotpm_ami "${src_ami}")"
    instance_id="$(launch_instance "${ami_id}")"

    if ! verify_tpm "${instance_id}"; then
        if "${ALLOW_UNVERIFIED}"; then
            warn 'continuing despite an unverified TPM (--allow-unverified)'
        else
            die "NitroTPM unverified on ${instance_id}. The instance is still running; inspect it, or run --destroy. Use --allow-unverified to accept this."
        fi
    fi

    # Credentials reached us through AWS_PROFILE, not a `default` profile. The
    # commands below run in a fresh shell, so they have to carry it themselves.
    local prof_flag='' prof_env=''
    if [[ -n "${AWS_PROFILE:-}" ]]; then
        prof_flag=" --profile ${AWS_PROFILE}"
        prof_env="AWS_PROFILE=${AWS_PROFILE} "
    fi

    cat >&2 <<EOF

────────────────────────────────────────────────────────────────
  Instance:  ${instance_id}
  AMI:       ${ami_id}
  Account:   ${ACCOUNT_ID}
  Region:    ${REGION}
  Tag:       ${TAG_KEY}=${TAG_VALUE}

  Connect (no inbound ports, per the guide):
    aws ssm start-session --target ${instance_id} --region ${REGION}${prof_flag}

  Tear down EVERYTHING (instance + AMIs + snapshot):
    ${prof_env}$0 --destroy --region ${REGION}
────────────────────────────────────────────────────────────────
EOF
}

need_value() {
    (($# >= 2)) || die "$1 requires a value"
}

main() {
    local action=''
    while (($# > 0)); do
        case "$1" in
            --create|--destroy|--status)
                [[ -z "${action}" ]] || die 'specify exactly one of --create/--destroy/--status'
                action="${1#--}"
                ;;
            --region)         need_value "$@"; REGION="$2"; shift ;;
            --instance-type)  need_value "$@"; INSTANCE_TYPE="$2"; shift ;;
            --account)        need_value "$@"; EXPECTED_ACCOUNT="$2"; shift ;;
            --yes)            ASSUME_YES=true ;;
            --allow-unverified) ALLOW_UNVERIFIED=true ;;
            -h|--help)        usage; exit 0 ;;
            *)                die "unknown argument: $1" ;;
        esac
        shift
    done
    [[ -n "${action}" ]] || { usage; exit 2; }

    preflight
    case "${action}" in
        create)  create ;;
        destroy) destroy ;;
        status)  status ;;
    esac
}

main "$@"
