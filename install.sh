#!/usr/bin/env bash
# ebpf-container-escape-framework - install / uninstall
# Usage: sudo ./install.sh [--prefix PATH] [--dry-run] [--uninstall]
#                        [--keep-config | --overwrite-config]
set -uo pipefail

PREFIX="/usr/local"
CONFIG_DIR="/etc/ebpf-edr"
SYSTEMD_DIR="/etc/systemd/system"
LOGROTATE_DIR="/etc/logrotate.d"
BIN_NAME="ebpf-edr"
SERVICE_NAME="ebpf-edr.service"
LIB_SUBDIR="lib/ebpf-edr"

DRY_RUN=0
UNINSTALL=0
KEEP_CONFIG=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_BIN="${ROOT}/userspace/ebpf_controller"
KERNEL_OBJ="${ROOT}/kernel/bpf_program.o"
EXAMPLE_CONFIG="${ROOT}/configs/config.toml"
UNIT_SRC="${ROOT}/ebpf-edr.service"

log() { printf '[install] %s\n' "$*"; }
err() { printf '[install] ERROR: %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }
run() { if (( DRY_RUN )); then printf '[dry-run] %s\n' "$*"; else "$@"; fi; }

usage() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --prefix PATH       Install prefix (default: /usr/local)
  --dry-run           Show actions without executing
  --uninstall         Remove all installed files
  --keep-config       Preserve existing /etc/ebpf-edr/config.toml (default)
  --overwrite-config  Overwrite existing config.toml
  -h, --help          This help
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --prefix) PREFIX="$2"; shift 2 ;;
            --dry-run) DRY_RUN=1; shift ;;
            --uninstall) UNINSTALL=1; shift ;;
            --keep-config) KEEP_CONFIG=1; shift ;;
            --overwrite-config) KEEP_CONFIG=0; shift ;;
            -h|--help) usage; exit 0 ;;
            *) die "unknown argument: $1" ;;
        esac
    done
}

require_root() { [[ $EUID -eq 0 ]] || die "must run as root (try: sudo $0 $*)"; }

check_systemd_health() {
    local state
    state="$(systemctl is-system-running 2>&1 || true)"
    case "$state" in
        running|degraded|starting|maintenance|"")
            # healthy or unknown-but-talking
            return 0
            ;;
        *"Transport endpoint"*|*"not connected"*|*"Failed to connect"*)
            die "systemd is not reachable on this host ($state). Reboot the VM and retry."
            ;;
        *)
            # any other state: warn but continue
            printf '[install] WARNING: systemctl is-system-running returned: %s\n' "$state" >&2
            return 0
            ;;
    esac
}

preflight() {
    log "preflight checks"
    check_systemd_health
    [[ -r /sys/kernel/btf/vmlinux ]] || die "BTF not available at /sys/kernel/btf/vmlinux"
    local kver kmaj kmin
    kver="$(uname -r)"; kmaj="$(echo "$kver" | cut -d. -f1)"; kmin="$(echo "$kver" | cut -d. -f2)"
    if (( kmaj < 6 )) || { (( kmaj == 6 )) && (( kmin < 12 )); }; then
        die "kernel $kver < 6.12"
    fi
    [[ -f "$USER_BIN" ]]   || die "missing $USER_BIN (run: make userspace)"
    [[ -f "$KERNEL_OBJ" ]] || die "missing $KERNEL_OBJ (run: make kernel)"
    [[ -f "$EXAMPLE_CONFIG" ]] || die "missing $EXAMPLE_CONFIG"
    [[ -f "$UNIT_SRC" ]]   || die "missing $UNIT_SRC"
    for t in systemctl install; do
        command -v "$t" >/dev/null 2>&1 || die "required tool not found: $t"
    done
    log "preflight OK (kernel $kver)"
}

do_install() {
    local sbin_dir="${PREFIX}/sbin"
    local lib_dir="${PREFIX}/${LIB_SUBDIR}"
    log "installing to $PREFIX"
    run install -d -m 0755 "$sbin_dir" "$lib_dir" "$CONFIG_DIR"
    run install -d -m 0755 "$LOGROTATE_DIR"

    run install -m 0755 "$USER_BIN"   "${sbin_dir}/${BIN_NAME}"
    run install -m 0644 "$KERNEL_OBJ" "${lib_dir}/bpf_program.o"

    if [[ -f "${CONFIG_DIR}/config.toml" ]]; then
        if (( KEEP_CONFIG )); then
            log "existing config preserved; new default at ${CONFIG_DIR}/config.toml.new"
            run install -m 0644 "$EXAMPLE_CONFIG" "${CONFIG_DIR}/config.toml.new"
        else
            log "overwriting existing config"
            run install -m 0644 "$EXAMPLE_CONFIG" "${CONFIG_DIR}/config.toml"
        fi
    else
        run install -m 0644 "$EXAMPLE_CONFIG" "${CONFIG_DIR}/config.toml"
    fi

    # systemd unit: substitute @PREFIX@
    local tmp_unit
    tmp_unit="$(mktemp)"
    sed "s|@PREFIX@|${PREFIX}|g" "$UNIT_SRC" > "$tmp_unit"
    run install -m 0644 "$tmp_unit" "${SYSTEMD_DIR}/${SERVICE_NAME}"
    rm -f "$tmp_unit"

    # logrotate
    local tmp_lr
    tmp_lr="$(mktemp)"
    cat > "$tmp_lr" <<'LR'
/var/log/ebpf_edr.json {
    daily
    rotate 5
    size 50M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
LR
    run install -m 0644 "$tmp_lr" "${LOGROTATE_DIR}/ebpf-edr"
    rm -f "$tmp_lr"

    run systemctl daemon-reload
    run systemctl enable "${SERVICE_NAME}"
    log "install complete"
    log "start  : systemctl start ${SERVICE_NAME}"
    log "status : systemctl status ${SERVICE_NAME}"
    log "logs   : journalctl -u ${SERVICE_NAME} -f"
}

do_uninstall() {
    log "uninstalling"
    run systemctl stop "${SERVICE_NAME}"
    run systemctl disable "${SERVICE_NAME}"
    run rm -f "${SYSTEMD_DIR}/${SERVICE_NAME}"
    run rm -f "${LOGROTATE_DIR}/ebpf-edr"
    run rm -f "${PREFIX}/sbin/${BIN_NAME}"
    run rm -rf "${PREFIX}/${LIB_SUBDIR}"
    run systemctl daemon-reload
    log "uninstall complete (config preserved at ${CONFIG_DIR})"
    log "to remove config : rm -rf ${CONFIG_DIR}"
    log "to remove logs   : rm -f /var/log/ebpf_edr.json*"
}

main() {
    parse_args "$@"
    require_root
    if (( UNINSTALL )); then
        do_uninstall
    else
        preflight
        do_install
    fi
}
main "$@"
