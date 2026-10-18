#!/bin/bash
clear
echo "=== 1. Creating Demo Config (with Canary) ==="
cat <<CONF > /tmp/demo_config.toml
mode = "audit"
[filter]
canary_paths = ["/tmp/secret-canary.txt"]
CONF
sleep 1

echo "=== 2. Starting eBPF EDR Daemon ==="
sudo ./userspace/ebpf_controller --config /tmp/demo_config.toml --bpf-obj kernel/bpf_program.o &
PID=$!
sleep 2

echo -e "\n=== 3. Running Adversary Emulation ==="
./emulation/adversary 2>&1 | tail -n 5

echo -e "\n=== 4. Triggering eBPF Canary File ==="
# Create the canary file and read it
echo "SuperSecretToken" > /tmp/secret-canary.txt
cat /tmp/secret-canary.txt > /dev/null 2>&1
sleep 1

echo -e "\n=== 5. Viewing EDR Logs (Showing Canary Alert) ==="
# We filter specifically for the Canary alert to make the demo punchy
sudo grep "Canary_Triggered" /var/log/ebpf_edr.json | tail -n 1 | cut -c 1-160

echo -e "\n=== Demo Complete. Shutting down. ==="
sudo kill $PID
sleep 1
