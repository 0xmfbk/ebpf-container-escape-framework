#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo -E bash scripts/patch_phase2_0.sh"
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BK="$ROOT/.phase2_0_patch_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BK"
for f in Makefile userspace/serializer.go kernel/bpf_program.c scripts/verify_phase2_0.sh; do
    mkdir -p "$BK/$(dirname "$f")"
    [[ -f "$f" ]] && cp -a "$f" "$BK/$f" || true
done
echo "==> backups in $BK"
