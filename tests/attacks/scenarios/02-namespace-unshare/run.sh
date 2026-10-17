#!/bin/bash
echo "[*] Simulating Namespace Escape (unshare)..."
# Attempt to create a new PID/Mount namespace
unshare --pid --mount --fork echo "Executed inside new namespace"
echo "[+] Attack executed."
