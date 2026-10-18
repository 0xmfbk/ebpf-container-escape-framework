# Kernel Compatibility Matrix

This framework targets Linux kernel **5.15 LTS and above**.

## Verified vs. Structurally Compatible
*   **Verified (6.12+):** The `sudo -E make verify` suite (82 PASS) has been executed successfully on Debian 13 (Kernel 6.12).
*   **Structurally Compatible (5.15 - 6.1):** By inspection, the BPF programs use only helpers and CO-RE features available since kernel 5.10. The framework is safe to deploy on Debian 12 (6.1) and Ubuntu 22.04 (5.15 LTS), but requires runtime verification by the user.

## Feature Matrix

| Feature / Helper | 5.15 LTS | 6.1 LTS | 6.12+ (Tested) | Notes |
|------------------|----------|---------|----------------|-------|
| `bpf_ringbuf_reserve/submit` | ✓ | ✓ | ✓ | Available since 5.8 |
| `bpf_get_current_task_btf` | ✓ | ✓ | ✓ | Available since 5.10 |
| `bpf_probe_read_user_str` | ✓ | ✓ | ✓ | Available since 5.5 |
| `bpf_get_current_cgroup_id` | ✓ | ✓ | ✓ | Available since 4.18 |
| `kprobe/__x64_sys_*` | ✓ | ✓ | ✓ | x86_64 syscall prefixes since 4.17 |
| `tracepoint/syscalls/sys_enter_*` | ✓ | ✓ | ✓ | Available since 4.7 |
| CO-RE Relocations (`.BTF`) | ✓ | ✓ | ✓ | Requires `CONFIG_DEBUG_INFO_BTF=y` |
| `struct event_t` (208 bytes) | ✓ | ✓ | ✓ | Wire format v3, invariant |

## vmlinux.h Pinning Policy

The repository commits a pinned `kernel/vmlinux.h` baseline. 
Because BTF dumped from a 6.12 host may contain types or fields that do not exist on 5.15, **the Makefile will not automatically generate `vmlinux.h` if it is missing.** 

To regenerate it from your host (which changes the minimum supported kernel), you must explicitly run:
```bash
make vmlinux-refresh
