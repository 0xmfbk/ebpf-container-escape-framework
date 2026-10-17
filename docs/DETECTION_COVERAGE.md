# Detection Coverage Matrix

This matrix maps every detection rule to its kernel hook, MITRE ATT&CK technique, and the reproducible attack test that proves it works.

| Rule ID | Action | Hook | MITRE | Attack Test | CI Status |
|---------|--------|------|-------|-------------|-----------|
| 1 | Container_Namespace_Unshare | `kprobe/__x64_sys_unshare` | T1611 | `tests/attacks/02-namespace-unshare` | ✅ Verified |
| 2 | Container_Pivot_Root_Escape | `kprobe/__x64_sys_pivot_root` | T1611 | `tests/attacks/02-namespace-unshare` | ✅ Verified |
| 3 | Sensitive_File_Access | `tracepoint/sys_enter_openat` | T1003.008 | `tests/attacks/03-shadow-access` | ✅ Verified |
| 4 | Process_Execution | `tracepoint/sys_enter_execve` | T1059.004 | `tests/attacks/run_all.sh` | ✅ Verified |
| 5 | Network_Connection | `tracepoint/sys_enter_connect` | T1071 | `emulation/adversary` | ✅ Verified |
| 6 | Process_Injection | `tracepoint/sys_enter_ptrace` | T1055.008 | `emulation/adversary` | ✅ Verified |
| 7 | Log_Tampering | `tracepoint/sys_enter_unlinkat` | T1562.001 | `emulation/adversary` | ✅ Verified |
| 8 | Ebpf_Tampering | `tracepoint/sys_enter_bpf` | T1562.001 | `emulation/adversary` | ✅ Verified |
| 9 | Perf_Event_Open | `tracepoint/sys_enter_perf_event_open` | T1562.001 | `emulation/adversary` | ✅ Verified |
| 10 | Suspicious_Mount | `tracepoint/sys_enter_mount` | T1611 | `tests/attacks/01-docker-socket` | ✅ Verified |
| 11 | Namespace_Switch | `tracepoint/sys_enter_setns` | T1611 | `emulation/adversary` | ✅ Verified |
| 12 | Chroot_Escape | `tracepoint/sys_enter_chroot` | T1611 | `emulation/adversary` | ✅ Verified |
| 13 | Executable_Memory | `tracepoint/sys_enter_mprotect` | T1620 | `emulation/adversary` | ✅ Verified |
