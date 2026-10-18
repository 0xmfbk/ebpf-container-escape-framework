# MITRE ATT&CK Coverage

| ID | Action | Severity | MITRE | Technique | Hook |
|----|--------|----------|-------|-----------|------|
| 1 | Container_Namespace_Unshare | HIGH | T1611 | Escape to Host | kprobe/__x64_sys_unshare |
| 2 | Container_Pivot_Root_Escape | CRITICAL | T1611 | Escape to Host | kprobe/__x64_sys_pivot_root |
| 3 | Sensitive_File_Access | HIGH | T1003.008 | OS Credential Dumping | tracepoint/sys_enter_openat + open |
| 4 | Process_Execution | INFO/MEDIUM | T1059.004 | Unix Shell | tracepoint/sys_enter_execve |
| 5 | Network_Connection | INFO/HIGH | T1071 | Application Layer Protocol | tracepoint/sys_enter_connect |
| 6 | Process_Injection | HIGH | T1055.008 | Process Injection: PTRACE | tracepoint/sys_enter_ptrace |
| 7 | Log_Tampering | HIGH | T1562.001 | Impair Defenses | tracepoint/sys_enter_unlinkat |
| 8 | Ebpf_Tampering | HIGH | T1562.001 | Impair Defenses: eBPF | tracepoint/sys_enter_bpf |
| 9 | Perf_Event_Open | MEDIUM | T1562.001 | Impair Defenses: perf | tracepoint/sys_enter_perf_event_open |
| 10 | Suspicious_Mount | HIGH | T1611 | Escape to Host: mount | tracepoint/sys_enter_mount |
| 11 | Namespace_Switch | HIGH | T1611 | Escape to Host: setns | tracepoint/sys_enter_setns |
| 12 | Chroot_Escape | HIGH | T1611 | Escape to Host: chroot | tracepoint/sys_enter_chroot |
| 13 | Executable_Memory | MEDIUM | T1620 | Reflective Code Loading | tracepoint/sys_enter_mprotect |
| 14 | Core_Pattern_Modification | CRITICAL | T1611 | Escape to Host: core_pattern | tracepoint/sys_enter_openat + open |
| 15 | Cgroup_Release_Agent | CRITICAL | T1611 | Escape to Host: cgroup release_agent | tracepoint/sys_enter_openat + open |

## Disabled by default

Actions 9 and 13 are chatty on production systems. They are attached but
suppressed at the kernel side via disabled_actions in config.toml.

## Enabling

Edit /etc/ebpf-edr/config.toml, set disabled_actions = [], then run
sudo systemctl reload ebpf-edr.