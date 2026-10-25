# v3.0.0 - Evasion-Proofing, Hardened Deployment & Observability

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
- **Least-privilege deployment:** the Kubernetes DaemonSet (Helm and raw
  manifests) no longer runs `privileged: true` — all capabilities dropped,
  only `BPF`/`PERFMON`/`SYS_ADMIN` added, seccomp `RuntimeDefault`.
- **SIEM credentials out of ConfigMaps:** new `secret.yaml` template (or
  bring your own via `secret.existingSecret`); the daemon expands
  `${SPLUNK_HEC_TOKEN}` in config at load time (this expansion was
  documented before but never actually implemented — sending the literal
  string as the auth header).

### 🏥 Self-Healing

- The daemon signals systemd (`Type=notify` + `WatchdogSec=30`) and touches
  a heartbeat file every 10s. A hung sensor is restarted by systemd or the
  Kubernetes liveness probe — verified live: `SIGSTOP` the daemon and it is
  detected and replaced within 30s.
- `systemd-analyze security` exposure: **2.7 OK** (syscall allow-list
  `@system-service @mount bpf perf_event_open`, address-family restriction,
  private devices, plus ProtectClock/Hostname/KernelLogs, RestrictNamespaces,
  `OOMScoreAdjust=-500`).
- Kubernetes: liveness/readiness probes on the heartbeat file,
  `checksum/config` rollout annotation, `priorityClassName:
  system-node-critical`, update strategy.

### 📈 Observability

- **Prometheus `/metrics`** (zero new dependencies, hand-rolled text
  exposition): per-action `ebpf_edr_events_total{action=...}`, drop and
  rate-limit counters, ring buffer errors, reload counters, lineage/cgroup
  cache entries and hit rates, sink delivery counters, queue depth,
  circuit-breaker state, `ebpf_edr_logging_degraded`, `ebpf_edr_build_info`.
  Off by default on hosts (`127.0.0.1:9400`), on by default in-cluster with
  `prometheus.io/scrape` annotations.
- **Sensor silence detection:** `[sensor] heartbeat_event = true` ships a
  synthetic INFO `Sensor_Heartbeat` alert every health tick so the SIEM can
  alert on absence (dead/muted/cut-off sensor). On by default in-cluster.
- The health line gained `degraded=` and `last_err=` fields, and the daemon
  now honors reloaded (`SIGHUP`) `[sensor]`/`[metrics]` settings.

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
idle CPU is verified separately at 0.40–0.70%.

- 15 BPF programs passing the kernel verifier (including `trace_openat2`)
- Lineage cache bounded at exactly 20000/20000 under 25,000 forks
- Ring buffer drops under 25k-fork stress: **0**
- All 8 Phase-2.4 hook actions observed end to end under PID-based
  self-exclusion
- Watchdog: `SIGSTOP`-frozen daemon detected and restarted by systemd
  within 30s (`Failed with result 'watchdog'` → auto-restart → streaming)
- `systemd-analyze security` exposure level: **2.7 OK**

## Install / Upgrade

    git pull
    make check-env                # read-only probe (new)
    sudo make deps                # only if the toolchain is incomplete (new)
    make kernel userspace emulation
    sudo -E make verify
    sudo ./install.sh             # preserves existing config.toml
