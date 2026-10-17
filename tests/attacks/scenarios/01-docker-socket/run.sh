#!/bin/bash
echo "[*] Simulating Docker Socket Escape attempt..."
# Mount docker.sock into an alpine container and try to list containers
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine sh -c "apk add curl >/dev/null && curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json > /dev/null"
echo "[+] Attack executed."
