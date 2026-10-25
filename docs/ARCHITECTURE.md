# Architecture

## Data Flow

Kernel tracepoints and kprobes (14 hooks) feed a single filter stage
(is_filtered + action_enabled lookup), then reserve a 208 byte record on
a 1 MiB ringbuf. Userspace reads the ringbuf into fixed size pooled
records, applies a per action token bucket, enriches with process lineage
and cgroup path from bounded LRU caches, and dispatches to a Sink.

The Sink encodes the event (JSON, ECS, OCSF, CEF, or LEEF) and routes it
to the configured transport (file, stdout, syslog, or webhook).

## Kernel Components

| Component | Type | Purpose |
|-----------|------|---------|
| events | ringbuf (1 MiB) | kernel to userspace transport |
| comm_allowlist | hash (256) | drop events by process name (user noise filter) |
| cgroup_allowlist | hash (1024) | drop events by cgroup ID |
| action_enabled | array (32) | per action kernel side enable/disable |
| canary_paths | hash (128) | O(1) exact-match canary lookup in open hooks |
| self_tgid | array (1) | daemon self-exclusion by tgid (unspoofable) |

## Userspace Components

| Package | Responsibility |
|---------|----------------|
| config.go | TOML schema, validation, precedence |
| ratelimit.go | per action token bucket |
| lineage.go | process ancestry cache (LRU 20000) |
| cgroup_path.go | cgroup path cache (LRU 5000) |
| container_resolver.go | cgroup ID to container ID + runtime |
| serializer.go | zero alloc JSON serializer |
| format_*.go | ECS, OCSF, CEF, LEEF encoders |
| output.go | Sink interface, network queue, circuit breaker |
| output_*.go | syslog and webhook transports |
| logger.go | rotation, dual sink (file + stdout) |

## Cache Bounds

| Cache | Capacity | Eviction | Hit Rate Target |
|-------|----------|----------|-----------------|
| container | 5000 | LRU | above 90 percent |
| lineage | 20000 | LRU | above 95 percent |
| cgroup path | 5000 | LRU | above 95 percent |
| network sink queue | 10000 | drop oldest | N/A |

## Event Versioning

Wire format is versioned (EVENT_VERSION, currently 3). Size is asserted
at compile time in C via _Static_assert and at test time in Go via
layout_test.go. A bump in EVENT_VERSION requires updating both sides.

## Kernel Programs (14 total)

| Program | Hook | Action IDs |
|---------|------|-----------|
| trace_unshare | kprobe/__x64_sys_unshare | 1 |
| trace_pivot_root | kprobe/__x64_sys_pivot_root | 2 |
| trace_openat | tracepoint/sys_enter_openat | 3, 14, 15 |
| trace_open | tracepoint/sys_enter_open | 3, 14, 15 |
| trace_execve | tracepoint/sys_enter_execve | 4 |
| trace_connect | tracepoint/sys_enter_connect | 5 |
| trace_ptrace | tracepoint/sys_enter_ptrace | 6 |
| trace_unlinkat | tracepoint/sys_enter_unlinkat | 7 |
| trace_bpf | tracepoint/sys_enter_bpf | 8 |
| trace_perf_event_open | tracepoint/sys_enter_perf_event_open | 9 |
| trace_mount | tracepoint/sys_enter_mount | 10 |
| trace_setns | tracepoint/sys_enter_setns | 11 |
| trace_chroot | tracepoint/sys_enter_chroot | 12 |
| trace_mprotect | tracepoint/sys_enter_mprotect | 13 |