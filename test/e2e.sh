#!/usr/bin/env bash
# test/e2e.sh — Run BATS tests inside containers across Linux distros
# Usage: test/e2e.sh [--runtime docker|podman] [--rebuild] [distro]

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly CONTAINER_DIR="${SCRIPT_DIR}/containers"
readonly IMAGE_PREFIX="git-harden-test"

# Distro matrix
readonly DISTROS=(ubuntu debian fedora alpine arch)

# Colors (empty if not a terminal)
if [ -t 2 ]; then
    readonly C_RED='\033[0;31m'
    readonly C_GREEN='\033[0;32m'
    readonly C_YELLOW='\033[0;33m'
    readonly C_BOLD='\033[1m'
    readonly C_RESET='\033[0m'
else
    readonly C_RED=''
    readonly C_GREEN=''
    readonly C_YELLOW=''
    readonly C_BOLD=''
    readonly C_RESET=''
fi

# Mutable state
RUNTIME=""
REBUILD=false
SKIP_HOST=false
TARGET_DISTRO=""

# Results tracking
RESULTS_DISTROS=""
RESULTS_STATUS=""
RESULTS_DURATION=""

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

die() {
    printf '%bError:%b %s\n' "$C_RED" "$C_RESET" "$1" >&2
    exit 1
}

info() {
    printf '%b[INFO]%b %s\n' "$C_YELLOW" "$C_RESET" "$1" >&2
}

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --runtime)
                [ $# -ge 2 ] || die "--runtime requires an argument (docker or podman)"
                RUNTIME="$2"
                shift 2
                ;;
            --rebuild)
                REBUILD=true
                shift
                ;;
            --skip-host)
                SKIP_HOST=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            -*)
                die "Unknown option: $1"
                ;;
            *)
                TARGET_DISTRO="$1"
                shift
                ;;
        esac
    done
}

usage() {
    cat >&2 <<'EOF'
Usage: test/e2e.sh [OPTIONS] [DISTRO]

Run BATS tests inside containers across Linux distributions.

Options:
  --runtime <docker|podman>   Container runtime (auto-detected if omitted)
  --rebuild                   Force image rebuild ignoring cache
  --skip-host                 Skip host interactive tests (run containers only)
  --help, -h                  Show this help

Distros: ubuntu, debian, fedora, alpine, arch

Examples:
  test/e2e.sh                 # Run all distros
  test/e2e.sh alpine          # Run Alpine only
  test/e2e.sh --runtime podman fedora  # Use Podman, Fedora only
EOF
}

# ------------------------------------------------------------------------------
# Runtime detection
# ------------------------------------------------------------------------------

detect_runtime() {
    if [ -n "$RUNTIME" ]; then
        if ! command -v "$RUNTIME" >/dev/null 2>&1; then
            die "${RUNTIME} is not installed"
        fi
        return
    fi

    local has_docker=false
    local has_podman=false

    if command -v docker >/dev/null 2>&1; then
        has_docker=true
    fi
    if command -v podman >/dev/null 2>&1; then
        has_podman=true
    fi

    if [ "$has_docker" = true ]; then
        RUNTIME="docker"
    elif [ "$has_podman" = true ]; then
        RUNTIME="podman"
    else
        die "Neither docker nor podman found. Install one of them:\n  brew install docker\n  brew install podman"
    fi

    # Verify the daemon is running
    if ! "$RUNTIME" info >/dev/null 2>&1; then
        die "${RUNTIME} daemon is not running. Is the ${RUNTIME} service started?"
    fi
}

# ------------------------------------------------------------------------------
# Build & run
# ------------------------------------------------------------------------------

build_image() {
    local distro="$1"
    local containerfile="${CONTAINER_DIR}/Containerfile.${distro}"
    local image_name="${IMAGE_PREFIX}:${distro}"

    if [ ! -f "$containerfile" ]; then
        die "Containerfile not found: $containerfile"
    fi

    local build_args=()
    if [ "$REBUILD" = true ]; then
        build_args+=("--no-cache")
    fi

    info "Building ${image_name}..."
    if ! "$RUNTIME" build \
        ${build_args[@]+"${build_args[@]}"} \
        -f "$containerfile" \
        -t "$image_name" \
        "$REPO_ROOT" 2>&1; then
        return 1
    fi
}

run_tests() {
    local distro="$1"
    local image_name="${IMAGE_PREFIX}:${distro}"

    info "Running BATS tests on ${distro}..."
    if ! "$RUNTIME" run \
        --rm \
        --network=none \
        "$image_name" \
        bash test/run.sh 2>&1; then
        return 1
    fi
}

run_interactive_tests() {
    local distro="$1"
    local image_name="${IMAGE_PREFIX}:${distro}"

    info "Running interactive tests on ${distro}..."
    if ! "$RUNTIME" run \
        --rm \
        --network=none \
        "$image_name" \
        bash test/interactive/run-all.sh 2>&1; then
        return 1
    fi
}

run_host_interactive() {
    info "Running interactive tests on host ($(uname -s))..."
    if ! bash "${SCRIPT_DIR}/run-interactive.sh" 2>&1; then
        return 1
    fi
}

# Generic entry that times a named test phase and records results
run_distro_entry() {
    local distro="$1"
    shift
    # Remaining args are the function + args to run
    local start_time
    start_time="$(date +%s)"

    printf '\n%b══ %s ══%b\n' "$C_BOLD" "$distro" "$C_RESET" >&2

    local status="PASS"
    if ! "$@"; then
        status="FAIL"
    fi

    local end_time
    end_time="$(date +%s)"
    local duration=$(( end_time - start_time ))

    RESULTS_DISTROS="${RESULTS_DISTROS}${distro}\n"
    RESULTS_STATUS="${RESULTS_STATUS}${status}\n"
    RESULTS_DURATION="${RESULTS_DURATION}${duration}s\n"

    if [ "$status" = "PASS" ]; then
        printf '%b  ✓ %s passed (%ds)%b\n' "$C_GREEN" "$distro" "$duration" "$C_RESET" >&2
    else
        printf '%b  ✗ %s %s (%ds)%b\n' "$C_RED" "$distro" "$status" "$duration" "$C_RESET" >&2
    fi
}

run_container_phases() {
    local distro="$1"
    if ! build_image "$distro"; then
        return 1
    fi
    if ! run_tests "$distro"; then
        return 1
    fi
    if ! run_interactive_tests "$distro"; then
        return 1
    fi
}

run_distro() {
    local distro="$1"
    run_distro_entry "$distro" run_container_phases "$distro"
}

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------

print_summary() {
    printf '\n%b══ Summary ══%b\n' "$C_BOLD" "$C_RESET" >&2
    printf '%-12s %-20s %s\n' "DISTRO" "STATUS" "DURATION" >&2
    printf '%-12s %-20s %s\n' "------" "------" "--------" >&2

    local distros_arr status_arr duration_arr
    IFS=$'\n' read -r -d '' -a distros_arr <<< "$(printf '%b' "$RESULTS_DISTROS")" || true
    IFS=$'\n' read -r -d '' -a status_arr <<< "$(printf '%b' "$RESULTS_STATUS")" || true
    IFS=$'\n' read -r -d '' -a duration_arr <<< "$(printf '%b' "$RESULTS_DURATION")" || true

    local i=0
    local any_failed=false
    while [ "$i" -lt "${#distros_arr[@]}" ]; do
        local d="${distros_arr[$i]}"
        local s="${status_arr[$i]}"
        local t="${duration_arr[$i]}"
        [ -z "$d" ] && { i=$((i + 1)); continue; }

        local color="$C_GREEN"
        if [ "$s" != "PASS" ]; then
            color="$C_RED"
            any_failed=true
        fi
        printf '%b%-12s %-20s %s%b\n' "$color" "$d" "$s" "$t" "$C_RESET" >&2
        i=$((i + 1))
    done

    if [ "$any_failed" = true ]; then
        return 1
    fi
    return 0
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

main() {
    parse_args "$@"
    detect_runtime

    info "Using runtime: ${RUNTIME}"

    # Run interactive tests on the host first (covers macOS ssh-keygen)
    if [ "$SKIP_HOST" = true ]; then
        info "Skipping host interactive tests (--skip-host)"
    elif command -v tmux >/dev/null 2>&1; then
        run_distro_entry "host" run_host_interactive
    else
        info "tmux not found — skipping host interactive tests (install with: brew install tmux)"
    fi

    if [ -n "$TARGET_DISTRO" ]; then
        # Validate distro name
        local valid=false
        for d in "${DISTROS[@]}"; do
            if [ "$d" = "$TARGET_DISTRO" ]; then
                valid=true
                break
            fi
        done
        if [ "$valid" = false ]; then
            die "Unknown distro: ${TARGET_DISTRO}. Available: ${DISTROS[*]}"
        fi

        run_distro "$TARGET_DISTRO"
    else
        for d in "${DISTROS[@]}"; do
            run_distro "$d"
        done
    fi

    print_summary
}

main "$@"
