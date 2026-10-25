#!/usr/bin/env bash
# Adversary emulation coverage assertions.
# Requires the daemon to be running (systemd or foreground).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EMUL="${ROOT}/emulation/adversary"
LOG_FILE="/var/log/ebpf_edr.json"
DAEMON_CONFIG="/etc/ebpf-edr/config.toml"

# Running this suite is the explicit opt-in for the adversary harness.
export EDR_EMULATION_CONFIRMED=1

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

# Back up the audit log before truncating it for a clean observation
# window, and restore it on any exit path: this file is the evidence
# trail the sensor exists to protect, not scratch space for tests.
LOG_BACKUP="${LOG_FILE}.test-backup.$$"
BACKED_UP=0
if [[ -f "$LOG_FILE" ]]; then
    cp "$LOG_FILE" "$LOG_BACKUP" || { echo "cannot back up $LOG_FILE"; exit 1; }
    BACKED_UP=1
fi
restore_log() {
    if (( BACKED_UP )); then
        cat "$LOG_BACKUP" >> "$LOG_FILE" 2>/dev/null || true
        rm -f "$LOG_BACKUP"
    fi
}
trap restore_log EXIT

: > "$LOG_FILE" 2>/dev/null || { echo "cannot truncate $LOG_FILE"; exit 1; }

log "running adversary emulation..."
"$EMUL" >/dev/null 2>&1 || true
sleep 2

# Canary probe: if the running daemon has canary paths configured, touch
# the first one and expect a Canary_Triggered alert. Soft check — a
# daemon without canaries configured reports WARN, not FAIL.
probe_canary() {
    local canary
    canary="$(sed -n 's/^[[:space:]]*canary_paths[[:space:]]*=[[:space:]]*\[\s*"\([^"]*\)".*/\1/p' \
        "$DAEMON_CONFIG" 2>/dev/null | head -n1)"
    if [[ -z "$canary" ]]; then
        log "WARN canary: no canary_paths configured in $DAEMON_CONFIG; skipping canary check"
        return 2
    fi
    head -c 1 "$canary" >/dev/null 2>&1 || dd if="$canary" of=/dev/null bs=1 count=1 2>/dev/null || true
    sleep 1
    if grep -q '"action":"Canary_Triggered"' "$LOG_FILE"; then
        log "PASS action: Canary_Triggered"
        return 0
    fi
    log "FAIL action: Canary_Triggered not observed after touching $canary"
    return 1
}

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

# openat2 coverage: the emulation fires openat2 on a path that
# prefix-matches the /etc/shadow rule; only sys_enter_openat2 can emit
# this exact target string.
if grep -q '"target":"/etc/shadow-openat2-probe"' "$LOG_FILE"; then
    log "PASS hook: sys_enter_openat2"
    PASS=$((PASS+1))
else
    log "FAIL hook: sys_enter_openat2 (openat2 bypass probe not detected)"
    FAIL=$((FAIL+1))
fi

probe_canary
rc=$?
if (( rc == 0 )); then
    PASS=$((PASS+1))
elif (( rc == 1 )); then
    FAIL=$((FAIL+1))
fi

log "summary: PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
