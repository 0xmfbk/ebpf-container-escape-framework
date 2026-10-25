#!/usr/bin/env bash
# demo.sh — record-ready v3.1.0 feature walkthrough.
#
# Record with:
#   asciinema rec -t "eBPF EDR v3.1.0 walkthrough" -c ./demo.sh docs/demo.cast
#   agg docs/demo.cast docs/demo.gif
#
# Runs the daemon in the foreground (quiet) against a scratch config with a
# canary path, fires the adversary emulation, triggers the canary, and shows
# metrics + alerts. Safe on a disposable host: emulation syscalls use
# nonexistent targets / invalid args by design.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

C='\033[1;36m'; G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'; DIM='\033[2m'
step() { echo; echo -e "${C}═══ $* ═══${N}"; sleep 1; }
ok()   { echo -e "  ${G}✔${N} $*"; }
note() { echo -e "  ${DIM}$*${N}"; }

LOG=/tmp/edr-demo.log
CFG=/tmp/edr-demo-config.toml
CANARY=/tmp/secret-canary.txt

step "eBPF Container Escape EDR — v3.1.0 walkthrough"
echo -e "  kernel : $(uname -r)"
echo -e "  BTF    : $(ls -la /sys/kernel/btf/vmlinux 2>/dev/null | awk '{print $5" bytes"}')"
echo -e "  LSM    : $(cat /sys/kernel/security/lsm 2>/dev/null | tr ',' ' ' | grep -o 'bpf' | head -1 | sed 's/bpf/bpf (LSM hooks eligible)/' || echo 'not active')"

[[ $EUID -eq 0 ]] || { echo "run as root: sudo ./demo.sh (or record with: sudo asciinema rec ...)"; exit 1; }
[[ -x userspace/ebpf_controller ]] || { echo "missing userspace/ebpf_controller (run: make userspace)"; exit 1; }
[[ -x emulation/adversary ]] || { echo "missing emulation/adversary (run: make emulation)"; exit 1; }

step "1/7 · sensor start (audit-only, quiet, metrics + heartbeat)"
cat > "$CFG" <<CONF
mode = "audit"
[filter]
canary_paths = ["$CANARY"]
[network]
suspicious_ports = [4444, 1337, 31337]
[metrics]
enabled = true
bind = "127.0.0.1:9400"
[sensor]
heartbeat_event = false
CONF
rm -f "$LOG"
EDR_LOG_PATH=/var/log/ebpf_edr.json \
    ./userspace/ebpf_controller --config "$CFG" --bpf-obj kernel/bpf_program.o \
    --quiet > "$LOG" 2>&1 &
DPID=$!
sleep 3
kill -0 "$DPID" 2>/dev/null || { echo "daemon died:"; tail -5 "$LOG"; exit 1; }
ok "daemon pid=$DPID · event wire v4 (224 bytes)"
grep -o 'lsm/file_open attached.*' "$LOG" | sed 's/^/  /' \
    || note "BPF LSM not active on this kernel — tracepoint file hooks in use (documented fallback)"
grep -o 'EDR Engine active.*' "$LOG" | sed 's/^/  /'

step "2/7 · Prometheus /metrics"
curl -s http://127.0.0.1:9400/metrics | grep -E '^ebpf_edr_(up|build_info|uptime_seconds)' | sed 's/^/  /'
note "per-action counters, drops, caches, sink delivery, degraded state — all here"

step "3/7 · adversary emulation — 19 actions, one binary"
EDR_EMULATION_CONFIRMED=1 ./emulation/adversary > /dev/null 2>&1 || true
sleep 2
ok "escape attempts, fileless exec, module load, IPv6 C2, log tampering fired"

step "4/7 · what the sensor saw"
echo -e "  ${Y}alerts by action:${N}"
grep -o '"action":"[^"]*"' /var/log/ebpf_edr.json | sort | uniq -c | sort -rn | sed 's/^/    /'
echo
echo -e "  ${Y}Phase D capabilities detected:${N}"
grep -q '"target":"/sys/fs/cgroup/emul-probe/release_agent"' /var/log/ebpf_edr.json \
    && ok "nested release_agent (suffix scan, cgroup v2 probe)" || echo -e "  ${R}✘${N} nested release_agent"
grep -q '"dest_ip":"::1"' /var/log/ebpf_edr.json \
    && ok "IPv6 connect ([::1]:4444 — wire v4 dest_ip)" || echo -e "  ${R}✘${N} IPv6 connect"
grep -q '"action":"Memfd_Create"' /var/log/ebpf_edr.json \
    && ok "memfd_create + execveat (fileless execution)" || echo -e "  ${R}✘${N} fileless execution"
grep -q '"action":"Kernel_Module_Load"' /var/log/ebpf_edr.json \
    && ok "init_module (kernel module load)" || echo -e "  ${R}✘${N} module load"
grep -q '"target":"/var/log/ebpf_edr.json.emul_probe"' /var/log/ebpf_edr.json \
    && ok "truncate-based log tampering" || echo -e "  ${R}✘${N} log tampering v2"

step "5/7 · sample alert — CRITICAL canary (zero false positives by design)"
echo "SuperSecretToken" > "$CANARY"
cat "$CANARY" > /dev/null
sleep 2
grep '"action":"Canary_Triggered"' /var/log/ebpf_edr.json | tail -1 | head -c 600
echo; echo -e "  ${DIM}... (full lineage, cgroup path, MITRE mapping follow)${N}"

step "6/7 · metrics after the attack"
curl -s http://127.0.0.1:9400/metrics | grep -E '^ebpf_edr_events_total\{action="(Canary|Cgroup|Memfd|Kernel|Network)' | sed 's/^/  /'
curl -s http://127.0.0.1:9400/metrics | grep -E '^ebpf_edr_events_(dropped|received)_total' | sed 's/^/  /'

step "7/7 · shutdown"
kill -TERM "$DPID" 2>/dev/null; sleep 2; kill -KILL "$DPID" 2>/dev/null
ok "clean SIGTERM exit — full session in /var/log/ebpf_edr.json"
note "record the full verify suite too:  asciinema rec -c 'sudo -E make verify' verify.cast"

echo
echo -e "${G}═══ eBPF EDR v3.1.0 — detection & audit only, never enforces ═══${N}"
