#!/bin/bash
echo "[*] Simulating Sensitive File Access (/etc/shadow)..."
cat /etc/shadow > /dev/null 2>&1 || true
echo "[+] Attack executed."
