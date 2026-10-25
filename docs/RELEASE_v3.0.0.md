# v3.0.0 - Evasion-Proofing, openat2 Coverage & Failure-Mode Hardening

## What's New in v3.0.0

### 🎯 Detection: `openat2` No Longer Bypasses File Rules

Added a 15th BPF program on `tracepoint/syscalls/sys_enter_openat2`. Before
this release, a single `openat2()` call — available since kernel 5.6 —
silently bypassed **all six file-based rules**: canary files, `/etc/shadow`,
runtime sockets (docker.sock / containerd.sock / crio / k3s), `core_pattern`,
`modprobe`, `uevent_helper`, and cgroup `release_agent`. open, openat and
openat2 now share one in-kernel classifier (the duplicated open/openat
handlers were merged in the process).

### 🛡️ Security

- **Closed the comm-spoofing evasion.** The sensor previously auto-added
  `ebpf-edr` / `ebpf_controller` to the kernel comm allowlist, so any process
  could call `prctl(PR_SET_NAME, "ebpf-edr")` and become invisible to every
  rule. Self-exclusion is now **PID-based**: the daemon publishes its tgid
  into a kernel-side `self_tgid` map, which an attacker cannot acquire.
- **Kernel data integrity:** events are zero-initialized after
  `bpf_ringbuf_reserve()`. Reserved ring memory is not zeroed, so stale bytes
  from recycled slots no longer leak into `aux_*` fields of unrelated alerts
  shipped to the SIEM.

### ⚙️ Reliability (silent failures are now loud — or self-healing)

- Transient ring buffer read errors retry with capped backoff instead of
  terminating the sensor; only a closed reader exits.
- A failed log rotation no longer permanently and silently disables file
  alerting: the logger degrades visibly (single warning, not per-event spam),
  retries reopening once per second, and logs recovery.
- Sink hardening: circuit breaker opens at most once per outage with exactly
  one cooldown reset; `Flush()` reports what is still queued/in-flight
  instead of always claiming success; events submitted after shutdown are
  counted as dropped; persistent transport failures are logged (rate-limited).
- Fixed a double-close panic in the K8s resolver and a data race in hostname
  caching.

### 🧰 Developer & Operator Experience

- **`make deps` / `make check-env`**: one-shot Debian/Ubuntu/WSL2 toolchain
  bootstrap — clang, libbpf headers, bpftool, python3, and the official Go
  toolchain (downloaded from go.dev, sha256-verified, symlinked into
  `/usr/local/bin` so it wins over older distro Go). `check-env` is a
  read-only probe of toolchain + kernel suitability (BTF, tracefs, cgroup v2,
  systemd, WSL2 detection). New `docs/WSL2.md`.
- `install.sh`: strict mode (`set -euo pipefail`) and atomic temp-then-rename
  installs — an interrupted install can no longer leave a truncated binary
  that systemd would execute.
- The verification stage that removed **all** Docker containers and restarted
  the Docker daemon is now opt-in via `EDR_VERIFY_DESTRUCTIVE=1`.
- The adversary emulation harness refuses to run without
  `EDR_EMULATION_CONFIRMED=1` (all in-repo callers set it automatically);
  ptrace now targets a disposable child instead of host PID 1, and the `/tmp`
  bind mount is unmounted after the syscall fires.

### 🧪 New Test Coverage

- `make test-attacks` now asserts canary triggering (soft-skip when no
  canary is configured) and openat2 coverage via a probe target only
  `sys_enter_openat2` can emit.
- The attack suite backs up and restores the audit log instead of truncating
  it destructively.

### ⚠️ Behavior Changes

- `comm_allowlist` is no longer auto-populated (it was the spoofing hole);
  user-configured entries continue to work as a noise filter.
- The destructive Docker verify stage and the adversary harness are now
  explicitly gated (see above).
- Kernel event ordering: `action_enabled` is checked before the comm/cgroup
  filter — disabled actions now short-circuit before any per-event filter
  work on the hot openat/mprotect paths.

### 🧪 Verification Evidence

**81 PASS / 3 WARN / 0 FAIL (core) + 7 PASS / 0 FAIL (SIEM)** on kernel
`6.12.111+deb13-amd64` (Debian 13). Two WARNs are the intentional Docker
stage opt-in notice; the third is the synthetic perf workload's CPU reading —
idle CPU is verified separately at 0.40%.

- 15 BPF programs passing the kernel verifier (including `trace_openat2`)
- Lineage cache bounded at exactly 20000/20000 under 25,000 forks
- Ring buffer drops under 25k-fork stress: **0**
- All 8 Phase-2.4 hook actions observed end to end under PID-based
  self-exclusion

## Install / Upgrade

    git pull
    make check-env                # read-only probe (new)
    sudo make deps                # only if the toolchain is incomplete (new)
    make kernel userspace emulation
    sudo -E make verify
    sudo ./install.sh             # preserves existing config.toml
