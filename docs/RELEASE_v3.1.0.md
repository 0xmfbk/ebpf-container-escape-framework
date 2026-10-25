# v3.1.0 - Detection Strength: IPv6, BPF LSM, Fileless & Log-Tamper Coverage

## What's New in v3.1.0

### 🎯 BPF LSM: Resolved-Path File Detection

When the kernel's active LSM list includes `bpf`, the sensor now attaches
`lsm/file_open` and classifies the **kernel-resolved** path (via
`bpf_d_path`) instead of user-supplied filename strings. This closes, in
one architectural step:

- **io_uring-driven opens** (`IORING_OP_OPENAT` executes without any
  `sys_enter_openat` tracepoint)
- the user-space filename race (TOCTOU between string copy and resolution)

On successful attach the open tracepoints go passive (kernel-side
`file_hook_lsm` flag), so every file event is emitted exactly once. The
program is audit-only and always returns 0. Kernels without BPF LSM keep
the v3.0.0 tracepoint behavior — load-time probing and fallback are fully
automatic (`[-] lsm/file_open attached` vs
`[-] BPF LSM not active...` in the logs).

### 🌐 IPv6 Network Visibility (wire format v4)

`connect()` with `AF_INET6` sockaddrs was silently dropped; C2 traffic
over IPv6 loopback or v6 networks was invisible. The event wire format
grows to **v4, 224 bytes** with a full 16-byte `dest_ip`; IPv4 events
zero-fill the tail and render as dotted quad, IPv6 as native notation
(`[::1]:4444` in `target`).

### 🗂️ New Actions (17–19)

| # | Action | Severity | MITRE | Covers |
|---|--------|----------|-------|--------|
| 17 | Memfd_Create | MEDIUM | T1055.012 | anonymous executable memory (fileless payloads) |
| 18 | Execveat | MEDIUM | T1620 | fileless execution (memfd/fd-based exec) |
| 19 | Kernel_Module_Load | HIGH | T1547.006 | `init_module` / `finit_module` |

### 🧹 Log Tampering v2

Deleting the audit log was detected; wiping or moving it was not. Now
covered: `truncate`, `rename`, `renameat`, `renameat2`, and write-intent
opens (`O_WRONLY`/`O_RDWR`/`O_TRUNC`) of `/var/log/ebpf_edr*`.

### 🔍 Smarter Existing Rules

- **release_agent suffix scan:** any `release_agent` / `notify_on_release`
  path anywhere under `/sys/fs/cgroup/` (nested and delegated cgroup v1
  hierarchies), not just 8 hard-coded paths.
- **`unshare(CLONE_NEWUSER)`** elevates Container_Namespace_Unshare to
  CRITICAL — the classic escape precursor.
- **Configurable suspicious ports:** `[network].suspicious_ports`
  (live-reloadable via SIGHUP); severity tuning no longer requires a
  rebuild.

### ⚠️ Wire Format Change (v3 → v4)

The kernel wire format is now **224 bytes, version 4**. C/Go layout
assertions and the verification suite enforce the new ABI. Userspace
rejects stale v3 records with `ver_mismatch` accounting, so a partially
upgraded deployment (old object file, new daemon) fails visibly instead
of misparsing.

## 🧪 Verification

Run `sudo -E make verify` on kernel 6.12: stage 1 now probes all 21
syscall tracepoints plus BPF LSM availability, stage 3 asserts the
v4/224-byte layout, and stage 13 requires the three new actions plus the
nested release_agent, IPv6, and truncate-tampering probes from the
adversary harness.

## Upgrade

    git pull
    make kernel userspace emulation   # rebuild BOTH sides (wire v4)
    sudo ./install.sh                 # installs new binary + object; config preserved
    sudo systemctl restart ebpf-edr

Note: the daemon and the BPF object must be upgraded together — a v3
object with a v4 daemon shows non-zero `ver_mismatch` in the health line.
