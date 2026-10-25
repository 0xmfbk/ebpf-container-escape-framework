#!/bin/bash
clear
echo -e "\033[1;36m=== 1. Starting eBPF EDR Daemon (Audit-Only) ===\033[0m"
sleep 1

# Create the config #
cat <<CONF > /tmp/demo_config.toml
mode = "audit"
[filter]
canary_paths = ["/tmp/secret-canary.txt"]
CONF

# Start the daemon, suppress its stdout so it doesn't spam the screen
sudo ./userspace/ebpf_controller --config /tmp/demo_config.toml --bpf-obj kernel/bpf_program.o > /dev/null 2>&1 &
PID=$!
sleep 2
echo -e "  \033[32m[OK]\033[0m EDR Engine active. Monitoring kernel syscalls..."

echo -e "\n\033[1;36m=== 2. Simulating Advanced Adversary Attack ===\033[0m"
sleep 1
# Run the adversary emulation (triggers pivot_root, core_pattern, etc.)
sudo EDR_EMULATION_CONFIRMED=1 ./emulation/adversary > /dev/null 2>&1
echo -e "  \033[32m[OK]\033[0m Container escape attempts simulated."

echo -e "\n\033[1;36m=== 3. Triggering eBPF Canary File ===\033[0m"
sleep 1
echo "SuperSecretToken" > /tmp/secret-canary.txt
cat /tmp/secret-canary.txt > /dev/null 2>&1
echo -e "  \033[32m[OK]\033[0m Canary file accessed."
sleep 1

echo -e "\n\033[1;36m=== 4. EDR Alert Dashboard (CRITICAL Alerts Only) ===\033[0m"
sleep 1

# Use jq to parse the log and print a beautiful UI (filtering only CRITICAL)
sudo cat /var/log/ebpf_edr.json | jq -r '
  select(.severity == "CRITICAL") | 
  "\n\u001b[1;31m🚨 ALERT: \u001b[1;37m" + .action + "\u001b[0m" +
  "\n   ├─ \u001b[1;33mSeverity:\u001b[0m " + .severity +
  "\n   ├─ \u001b[1;33mCommand: \u001b[0m " + .command +
  "\n   ├─ \u001b[1;33mMITRE:   \u001b[0m " + .mitre_id + " (" + .mitre_technique + ")" +
  "\n   └─ \u001b[1;33mLineage: \u001b[0m " + .lineage_summary + "\n"
' | tail -n 25

echo -e "\n\033[1;36m=== Demo Complete. Shutting down cleanly. ===\033[0m"
sudo kill $PID
sleep 1
