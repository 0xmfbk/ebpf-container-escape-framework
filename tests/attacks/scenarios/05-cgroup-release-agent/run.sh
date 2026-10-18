#!/bin/bash
echo "[*] Simulating cgroup release_agent access..."
found=0
while IFS= read -r f; do
    cat "$f" >/dev/null 2>&1 || true
    found=1
done < <(find /sys/fs/cgroup -maxdepth 4 \
           \( -name 'release_agent' -o -name 'notify_on_release' \) \
           -type f 2>/dev/null)

if [ "$found" = 0 ]; then
    echo "[!] No release_agent/notify_on_release files present (typical on cgroup v2 hosts)."
    echo "    Attempting direct path to fire the tracepoint anyway..."
    cat /sys/fs/cgroup/release_agent >/dev/null 2>&1 || true
fi
echo "[+] Attack executed."