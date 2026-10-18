# eBPF Container Escape Detection & Runtime Audit EDR

<p align="center">
  <img src="docs/demo.gif" alt="Demo" width="800">
</p>

> **Detection & audit only. Non enforcing sensor.**
> No BPF program returns `-EPERM`; no syscall is blocked. This agent is a
> runtime observation plane, not a prevention plane. See
> [`docs/SECURITY.md`](docs/SECURITY.md#audit-only-mode) and
> [`THREAT_MODEL.md`](THREAT_MODEL.md).

An audit only Linux EDR agent built with eBPF (kernel side, C) and a
high efficiency Go daemon (user space). Targets Debian 13 / kernel 6.12+
with BTF enabled. Emits structured JSON with full process lineage and
cgroup context, backed by a zero allocation pipeline and bounded caches.

**Status:** Phase 2.6 complete. 13 MITRE ATT&CK techniques across 15 actions.
Verified end to end on kernel 6.12.111, with structural support for Linux 5.15 LTS.

## Coverage

| # | Action | Severity | MITRE | Hook |
|---|--------|----------|-------|------|
| 1 | Container_Namespace_Unshare | HIGH | T1611 | kprobe/__x64_sys_unshare |
| 2 | Container_Pivot_Root_Escape | CRITICAL | T1611 | kprobe/__x64_sys_pivot_root |
| 3 | Sensitive_File_Access | HIGH | T1003.008 | tracepoint/sys_enter_openat + open |
| 4 | Process_Execution | INFO/MEDIUM | T1059.004 | tracepoint/sys_enter_execve |
| 5 | Network_Connection | INFO/HIGH | T1071 | tracepoint/sys_enter_connect |
| 6 | Process_Injection | HIGH | T1055.008 | tracepoint/sys_enter_ptrace |
| 7 | Log_Tampering | HIGH | T1562.001 | tracepoint/sys_enter_unlinkat |
| 8 | Ebpf_Tampering | HIGH | T1562.001 | tracepoint/sys_enter_bpf |
| 9 | Perf_Event_Open | MEDIUM | T1562.001 | tracepoint/sys_enter_perf_event_open |
| 10 | Suspicious_Mount | HIGH | T1611 | tracepoint/sys_enter_mount |
| 11 | Namespace_Switch | HIGH | T1611 | tracepoint/sys_enter_setns |
| 12 | Chroot_Escape | HIGH | T1611 | tracepoint/sys_enter_chroot |
| 13 | Executable_Memory | MEDIUM | T1620 | tracepoint/sys_enter_mprotect |
| 14 | Core_Pattern_Modification | CRITICAL | T1611 | tracepoint/sys_enter_openat + open |
| 15 | Cgroup_Release_Agent | CRITICAL | T1611 | tracepoint/sys_enter_openat + open |

Actions 9 and 13 are attached but kernel side suppressed by default via
`disabled_actions` in `config.toml`.

## Architecture

Kernel hooks (14) feed a comm/cgroup filter, then an `action_enabled`
lookup, then a 1 MiB ringbuf carrying 208 byte records. Userspace reads
into a fixed pooled buffer, applies a per action token bucket, enriches
with process lineage and cgroup path from bounded LRU caches, and routes
through an Encoder + Sink to any destination.

Full details: `docs/ARCHITECTURE.md`.

## SIEM Integration

`ebpf edr` exports alerts to any SIEM via a format + transport layer.

```toml
[output]
format = "ecs"        # json | ecs | ocsf | cef | leef
target = "webhook"    # file | stdout | syslog | webhook

[output.webhook]
url         = "https://splunk.internal:8088/services/collector/event"
auth_header = "Splunk ${SPLUNK_HEC_TOKEN}"
splunk_hec  = true
```

Supported transports: file, stdout, syslog (UDP/TCP/TLS), HTTPS webhook.
Supported formats: native JSON, ECS 8.11, OCSF 1.3.0, CEF, LEEF 2.0.

Recipes for Splunk, Elastic, Sentinel, QRadar, and generic syslog:
`docs/SIEM_INTEGRATION.md`.

Absent `[output]`, behavior is byte identical to v1.x.

## Requirements

- Linux Kernel >= 5.15 LTS with `CONFIG_DEBUG_INFO_BTF=y` (`/sys/kernel/btf/vmlinux`)
- Tested on Debian 13 (Kernel 6.12). See `docs/KERNEL_COMPATIBILITY.md` for the full matrix.
- clang, gcc, Go >= 1.21, bpftool, libbpf headers
- Root with `CAP_BPF CAP_PERFMON CAP_SYS_ADMIN`

## Build

    make kernel        # kernel/bpf_program.o
    make userspace     # userspace/ebpf_controller
    make emulation     # emulation/adversary

## Verify (15 core stages + 2 SIEM stages)

    sudo -E make verify

Runs environment probe, build, C/Go struct layout assertion, BPF verifier
dry-run, runtime smoke, adversary emulation, performance, config matrix,
SIGHUP reload, idle CPU, lineage enrichment, cache bounds, new hooks,
format matrix, and webhook delivery.

## Install (systemd)

    sudo ./install.sh --dry-run
    sudo ./install.sh
    sudo ./install.sh --uninstall

Installs `/usr/local/sbin/ebpf-edr`,
`/usr/local/lib/ebpf-edr/bpf_program.o`,
`/etc/ebpf-edr/config.toml` (existing preserved; new default at `.new`),
`/etc/systemd/system/ebpf-edr.service`,
`/etc/logrotate.d/ebpf-edr`.

## Configuration

TOML at `/etc/ebpf-edr/config.toml`. Precedence: CLI > env (`EDR_*`) > file > defaults.

    mode = "audit"

    [log]
    path        = "/var/log/ebpf_edr.json"
    max_bytes   = 52428800
    max_backups = 5
    level       = "info"

    [filter]
    comm_allowlist   = []
    cgroup_allowlist = []

    [rates]
    events_per_sec = 200
    burst          = 400

    [container]
    cache_max_entries = 5000

    [context]
    lineage_max_depth  = 16
    lineage_cache_size = 20000
    cgroup_cache_size  = 5000

    disabled_actions = []

Reload: `sudo systemctl reload ebpf-edr`. `mode = "enforce"` is rejected;
this build is audit only.

## Event schema (v3, 208 bytes on the wire)

    {
      "timestamp": "2026-10-15T23:52:41Z",
      "pid": 1370, "ppid": 1369, "uid": 0,
      "start_time_ns": 180763002635,
      "command": "unix_chkpwd",
      "action": "Sensitive_File_Access",
      "target": "/etc/shadow",
      "severity": "HIGH",
      "mitre_id": "T1003.008",
      "mitre_technique": "OS Credential Dumping: /etc/shadow",
      "cgroup_id": 3874,
      "cgroup_path": "/user.slice/user-0.slice/session-3.scope",
      "runtime": "host",
      "lineage_summary": "systemd > sshd > bash > sudo > unix_chkpwd",
      "lineage": [
        {"pid": 1370, "ppid": 1369, "comm": "unix_chkpwd",
         "exe": "/usr/sbin/unix_chkpwd", "start_time_ns": 180763002635},
        {"pid": 1369, "ppid": 1368, "comm": "sudo",
         "exe": "/usr/bin/sudo", "start_time_ns": 180762998100}
      ]
    }

Fields `aux_u16`, `aux_u32`, `aux_u64` carry action specific context.

## Operations

Health line every 60s:

    [health] recv=N written=N dropped=N rate_limited=N parse_err=N
             ver_mismatch=N ringbuf_err=N reloads=N reload_fail=N
             chan=N/4096 lineage_cache=N/20000 lineage_hits=N
             lineage_misses=N cgroup_cache=N/5000
             sink_sent=N sink_failed=N sink_dropped=N sink_retries=N
             sink_queue=N sink_circuit=bool

Targets: `dropped` = 0, `ver_mismatch` = 0, `lineage_cache` under capacity.

## Development

| Target | Purpose |
|--------|---------|
| `make kernel` | Build BPF object |
| `make userspace` | Build daemon |
| `make emulation` | Build adversary harness |
| `make test` | Go unit tests |
| `make test-race` | Go tests with race detector |
| `make fuzz` | 60s fuzz per target |
| `make verify` | 15 stage core + 2 stage SIEM verification |
| `make verify-siem` | 2 stage SIEM verification only |
| `make ci` | Local CI: gofmt, vet, race, fuzz, verify |
| `make install` / `uninstall` | System install / removal |
| `make test-attacks` | Emulation coverage assertions |
| `make clean` | Remove build artifacts |

## Documentation

- `docs/ARCHITECTURE.md` - data flow, kernel programs, caches, versioning.
- `docs/OPERATIONS.md` - install, config, reload, troubleshooting.
- `docs/MITRE_MATRIX.md` - full technique mapping with hook names.
- `docs/SECURITY.md` - threat model, capabilities, sandbox, failure modes.
- `docs/SIEM_INTEGRATION.md` - Splunk, Elastic, Sentinel, QRadar recipes.
- `SECURITY.md` - vulnerability disclosure policy and supported versions.
- `CONTRIBUTING.md` - contribution workflow and local CI gate.
- `CODE_OF_CONDUCT.md` - community standards.
- `docs/KERNEL_COMPATIBILITY.md` - kernel floor (5.15 LTS), feature matrix, and vmlinux.h pinning policy.

## Verification evidence

Last full run (kernel 6.12.111+deb13-amd64): **79 PASS, 1 WARN, 0 FAIL**
across 15+2 stages. The one WARN is the synthetic perf workload's CPU
reading, idle CPU is verified separately at 0.40%.

## License

MIT
## Kubernetes & Docker (Phase 2.7)

The framework is designed to run as a Kubernetes DaemonSet to provide cluster wide EDR coverage.

### Build the Docker Image

    make docker-build

### Deploy to Kubernetes (Raw Manifests)

    make k8s-apply

This creates the `ebpf-edr` namespace, a ConfigMap for configuration, and a DaemonSet that runs on every node. Logs are sent to `stdout` by default, where they can be scraped by Fluent Bit, Vector, or Promtail.

### Deploy via Helm (Recommended)

    helm install ebpf-edr ./deploy/helm/ebpf-edr -n ebpf-edr --create-namespace

To send alerts to a SIEM webhook via Helm:

    helm install ebpf-edr ./deploy/helm/ebpf-edr -n ebpf-edr --create-namespace \
      --set config.output.target=webhook \
      --set config.output.webhook_url="https://splunk.internal:8088/services/collector/event" \
      --set config.output.webhook_token="Splunk ${SPLUNK_HEC_TOKEN}"

### Security Architecture

- **`hostPID: true`**: Required to map PIDs to cgroups for lineage.
- **`privileged: true`**: Required for `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`.
- **Host Mounts**: Mounts `/sys/kernel/btf/vmlinux` and `/sys/fs/bpf` from the host.
- **Resource Limits**: Default limits (256Mi memory, 500m CPU) ensure the DaemonSet cannot starve the node.
