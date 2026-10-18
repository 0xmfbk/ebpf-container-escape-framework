#!/bin/bash
echo "[*] Simulating core_pattern / kernel helper access..."
# Read-only open of each path — fires sys_enter_openat, which is what the
# sensor detects. Does not modify the host. Safe in CI and on dev machines.
for f in /proc/sys/kernel/core_pattern \
         /proc/sys/kernel/modprobe \
         /proc/sys/kernel/uevent_helper; do
    cat "$f" >/dev/null 2>&1 || true
done
echo "[+] Attack executed."