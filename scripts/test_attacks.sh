#!/usr/bin/env bash
# Adversary emulation coverage assertions.
# Requires the daemon to be running (systemd or foreground).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EMUL="${ROOT}/emulation/adversary"
LOG_FILE="/var/log/ebpf_edr.json"

REQUIRED_ACTIONS=(
    Container_Namespace_Unshare
    Container_Pivot_Root_Escape
    Sensitive_File_Access
    Process_Execution
    Network_Connection
    Process_Injection
    Log_Tampering
)
REQUIRED_MITRE=(T1611 T1003.008 T1055.008 T1562.001 T1071 T1059.004)

log() { printf '[test-attacks] %s\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "must run as root"; exit 1; }
[[ -x "$EMUL" ]] || { echo "missing $EMUL (run: make emulation)"; exit 1; }

if ! pgrep -f ebpf_controller >/dev/null 2>&1 && ! systemctl is-active --quiet ebpf-edr 2>/dev/null; then
    echo "daemon not running (start ebpf-edr.service or run userspace/ebpf_controller)"
    exit 1
fi

: > "$LOG_FILE" 2>/dev/null || { echo "cannot truncate $LOG_FILE"; exit 1; }

log "running adversary emulation..."
"$EMUL" >/dev/null 2>&1 || true
sleep 2

PASS=0; FAIL=0
for action in "${REQUIRED_ACTIONS[@]}"; do
    if grep -q "\"action\":\"$action\"" "$LOG_FILE"; then
        log "PASS action: $action"; PASS=$((PASS+1))
    else
        log "FAIL action: $action"; FAIL=$((FAIL+1))
    fi
done
for mitre in "${REQUIRED_MITRE[@]}"; do
    if grep -q "\"mitre_id\":\"$mitre\"" "$LOG_FILE"; then
        log "PASS mitre: $mitre"; PASS=$((PASS+1))
    else
        log "FAIL mitre: $mitre"; FAIL=$((FAIL+1))
    fi
done

log "summary: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
