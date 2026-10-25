# Security Model

## Threat Model

- Host kernel is trusted.
- EDR binary and config are root owned and immutable in production.
- Attackers may run as unprivileged users or compromised containers.
- Attackers cannot modify running EDR process memory or its BPF programs.

## Capabilities

| Capability | Reason |
|------------|--------|
| CAP_BPF | Load and attach BPF programs |
| CAP_PERFMON | Read kernel tracepoints |
| CAP_SYS_ADMIN | Attach kprobes to syscall entry points |

The systemd unit also enforces NoNewPrivileges, ProtectSystem=strict,
ProtectHome, PrivateTmp, MemoryDenyWriteExecute, RestrictRealtime,
LockPersonality, ProtectKernelTunables, ProtectKernelModules,
ProtectControlGroups.

## Self-Protection

- The daemon publishes its own tgid into the kernel-side `self_tgid` map
  at startup, so the agent does not alert on its own BPF/map syscalls.
  Filtering is PID-based: a comm-based allowlist was removed because any
  process could evade every rule via `prctl(PR_SET_NAME, "ebpf-edr")`.
- `comm_allowlist` remains a user-configured noise filter only and must
  not be relied on for self-protection.
- trace_unlinkat fires on unlink of /var/log/ebpf_edr*, catching log
  tampering attempts.

## Audit-Only Mode

This build is audit only. --mode=enforce is rejected at startup. No BPF
program returns -EPERM; no syscall is blocked. The system is a detection
plane, not a prevention plane.

## Failure Modes

| Failure | Behavior |
|---------|----------|
| Ringbuf full | Events dropped; counted in health log |
| /proc/PID read fails | Lineage emitted without that ancestor |
| Cache full | LRU evicts oldest entry |
| Config reload parse error | Current config preserved; counter incremented |
| BPF verifier rejects | Startup aborts; systemd Restart=on-failure |
| SIEM endpoint down | Network queue fills (10k max), then drops; circuit breaker trips after 5 failures |

## Out of Scope

- Enforcement (blocking syscalls)
- Binary attestation
- Protection against kernel level compromise