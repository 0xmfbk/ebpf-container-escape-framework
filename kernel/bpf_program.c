#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../common/common.h"

#define MATCH_STR(p, s) ({ \
    int _match = 1; \
    _Pragma("unroll") \
    for (int _i = 0; _i < sizeof(s) - 1; _i++) { \
        if (p[_i] != s[_i]) { _match = 0; break; } \
    } \
    _match; \
})


/* ================== Maps ================== */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, __u32);
} comm_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u32);
} cgroup_allowlist SEC(".maps");

/* MUST KEEP THIS MAP */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u32);
} action_enabled SEC(".maps");

/* ADDED FOR TASK 5 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, __u32);
} canary_paths SEC(".maps");

/* Daemon self-exclusion. Userspace publishes its own tgid here at startup
 * so the sensor's own bpf()/map activity does not self-alert. Unlike a
 * comm-based allowlist this cannot be spoofed via prctl(PR_SET_NAME).
 * Value 0 disables the check. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} self_tgid SEC(".maps");

/* Set to 1 by userspace after lsm/file_open attaches successfully. While
 * set, the open tracepoints emit only the attempt-based classes (canary,
 * release_agent); the LSM hook owns the resolved-path classes and would
 * otherwise duplicate those events. Attempt-based classes never move:
 * the LSM cannot see opens that fail path resolution. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} file_hook_lsm SEC(".maps");

/* ================== Helpers ================== */

static __always_inline int is_filtered(void)
{
    /* Self-exclusion by tgid first: the loaded daemon publishes its tgid
     * in self_tgid. An attacker cannot acquire the daemon's tgid, unlike
     * a comm name which is settable with prctl(PR_SET_NAME). */
    __u32 zero = 0;
    __u32 *self = bpf_map_lookup_elem(&self_tgid, &zero);
    if (self && *self && (__u32)(bpf_get_current_pid_tgid() >> 32) == *self)
        return 1;
    char comm[MAX_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (bpf_map_lookup_elem(&comm_allowlist, comm))
        return 1;
    __u64 cg = bpf_get_current_cgroup_id();
    if (bpf_map_lookup_elem(&cgroup_allowlist, &cg))
        return 1;
    return 0;
}

static __always_inline struct event_t *event_alloc(__u32 action_id)
{
    /* Cheapest gate first: a disabled action short-circuits before any
     * per-event filter work (comm read + two hash lookups). This matters
     * on the hot openat/mprotect hooks when an action is disabled. */
    __u32 *en = bpf_map_lookup_elem(&action_enabled, &action_id);
    if (!en || !*en)
        return NULL;
    if (is_filtered())
        return NULL;
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if (!e)
        return NULL;
    /* Reserved ringbuf memory is NOT zeroed. Without this memset, fields
     * a hook does not set (filename, dest_ip, aux_*) carry stale bytes
     * recycled from previously submitted events. */
    __builtin_memset(e, 0, sizeof(*e));
    return e;
}

static __always_inline void event_fill_common(struct event_t *e)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e->version       = EVENT_VERSION;
    e->cgroup_id     = bpf_get_current_cgroup_id();
    e->pid           = (__u32)(pid_tgid >> 32);
    e->uid           = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    /* Single task fetch serves both ppid and start_boottime. On failure
     * the fields stay zero (event was memset in event_alloc). */
    if (task) {
        struct task_struct *parent = NULL;
        if (bpf_core_read(&parent, sizeof(parent), &task->real_parent) == 0 && parent)
            bpf_core_read(&e->ppid, sizeof(e->ppid), &parent->tgid);
        bpf_core_read(&e->start_time_ns, sizeof(e->start_time_ns), &task->start_boottime);
    }

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline int is_shadow_path(const char *p)
{
    return MATCH_STR(p, "/etc/shadow");
}

static __always_inline int is_edr_log_path(const char *p)
{
    return MATCH_STR(p, "/var/log/ebpf_edr");
}

/* open(2) style flags for write-intent detection. */
#define O_WRONLY_VAL 0x1
#define O_RDWR_VAL   0x2
#define O_TRUNC_VAL  0x200

static __always_inline int has_write_intent(__u64 flags)
{
    return flags & (O_WRONLY_VAL | O_RDWR_VAL | O_TRUNC_VAL);
}

/* Container runtime control sockets. Prefix match via MATCH_STR; the
 * prefix form catches bind mounts at these canonical paths. */
static __always_inline int is_container_runtime_socket_path(const char *p)
{
    return MATCH_STR(p, "/var/run/docker.sock")
        || MATCH_STR(p, "/run/docker.sock")
        || MATCH_STR(p, "/var/run/containerd/containerd.sock")
        || MATCH_STR(p, "/run/containerd/containerd.sock")
        || MATCH_STR(p, "/var/run/crio/crio.sock")
        || MATCH_STR(p, "/run/crio/crio.sock")
        || MATCH_STR(p, "/run/k3s/containerd/containerd.sock");
}

/* Kernel-invoked user-space helper hijack vectors: writing to any of
 * these causes the kernel to exec an attacker-chosen binary on the host. */
static __always_inline int is_kernel_helper_path(const char *p)
{
    return MATCH_STR(p, "/proc/sys/kernel/core_pattern")
        || MATCH_STR(p, "/proc/sys/kernel/modprobe")
        || MATCH_STR(p, "/proc/sys/kernel/uevent_helper");
}

/* cgroup release_agent / notify_on_release. Suffix scan: matches these
 * files ANYWHERE under /sys/fs/cgroup/ (any cgroup v1 hierarchy or
 * delegated subtree), not just a fixed list of exact paths. On cgroup v2
 * the files do not exist, so the scan is dead weight there — acceptable
 * for the few-hundred-instruction bounded loop. Explicit char compares
 * (not string literals) keep the whole thing verifier-friendly. */
static __always_inline int is_release_agent_at(const char *p, int i)
{
    return p[i] == 'r' && p[i+1] == 'e' && p[i+2] == 'l' && p[i+3] == 'e'
        && p[i+4] == 'a' && p[i+5] == 's' && p[i+6] == 'e' && p[i+7] == '_'
        && p[i+8] == 'a' && p[i+9] == 'g' && p[i+10] == 'e' && p[i+11] == 'n'
        && p[i+12] == 't';
}

static __always_inline int is_notify_on_release_at(const char *p, int i)
{
    return p[i] == 'n' && p[i+1] == 'o' && p[i+2] == 't' && p[i+3] == 'i'
        && p[i+4] == 'f' && p[i+5] == 'y' && p[i+6] == '_' && p[i+7] == 'o'
        && p[i+8] == 'n' && p[i+9] == '_' && p[i+10] == 'r' && p[i+11] == 'e'
        && p[i+12] == 'l' && p[i+13] == 'e' && p[i+14] == 'a' && p[i+15] == 's'
        && p[i+16] == 'e';
}

static __always_inline int is_cgroup_release_agent_path(const char *p)
{
    if (!MATCH_STR(p, "/sys/fs/cgroup/"))
        return 0;
    for (int i = 0; i + 16 < MAX_FILENAME_LEN; i++) {
        if (p[i] == '\0')
            return 0;
        if (p[i] == 'r' && is_release_agent_at(p, i))
            return 1;
        if (p[i] == 'n' && is_notify_on_release_at(p, i))
            return 1;
    }
    return 0;
}

/* ================== Container escape ================== */

SEC("kprobe/__x64_sys_unshare")
int BPF_KPROBE(trace_unshare, int flags)
{
    struct event_t *e = event_alloc(ACTION_CONTAINER_NAMESPACE_UNSHARE);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_CONTAINER_NAMESPACE_UNSHARE;
    e->aux_u32 = (__u32)flags;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_pivot_root")
int BPF_KPROBE(trace_pivot_root)
{
    struct event_t *e = event_alloc(ACTION_CONTAINER_PIVOT_ROOT_ESCAPE);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_CONTAINER_PIVOT_ROOT_ESCAPE;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================== Sensitive file access ================== */

struct trace_event_raw_sys_enter_openat {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    __s64 dfd;
    const char *filename;
    __s64 flags;
    __s64 mode;
};

struct trace_event_raw_sys_enter_open {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    const char *filename;
    __s64 flags;
    __s64 mode;
};

/* openat2(dfd, filename, how, size): same leading layout as openat, so
 * filename sits at the same offset. Hooking it is required for coverage:
 * without it, opening core_pattern/docker.sock/canaries via openat2
 * (kernel 5.6+) would bypass every file rule below. `struct open_how`
 * is a UAPI type not present in vmlinux.h; a pointer to the incomplete
 * type is all we need since we never dereference it. */
struct trace_event_raw_sys_enter_openat2 {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    __s64 dfd;
    const char *filename;
    struct open_how *how;
    __s64 size;
};

/* Attempt-based classes: the ATTEMPT is the signal — the target may not
 * even exist (release_agent on cgroup v2 hosts, probed canary paths).
 * These always run on the open/openat/openat2 tracepoints, which fire at
 * syscall entry regardless of resolution; the LSM hook cannot see them
 * because security_file_open only runs after a successful open. */
static __always_inline __u32 classify_attempt_path(const char *path)
{
    if (bpf_map_lookup_elem(&canary_paths, path))
        return ACTION_CANARY_TRIGGERED;
    if (is_cgroup_release_agent_path(path))
        return ACTION_CGROUP_RELEASE_AGENT;
    return 0;
}

/* Resolved-path classes: targets that exist on real systems. When
 * lsm/file_open is attached it owns these (kernel-resolved path, io_uring
 * opens included); the tracepoints take over unchanged when it is not. */
static __always_inline __u32 classify_resolved_path(const char *path, __u64 flags)
{
    if (is_edr_log_path(path) && has_write_intent(flags))
        return ACTION_LOG_TAMPERING;
    if (is_shadow_path(path) || is_container_runtime_socket_path(path))
        return ACTION_SENSITIVE_FILE_ACCESS;
    if (is_kernel_helper_path(path))
        return ACTION_CORE_PATTERN_MODIFICATION;
    return 0;
}

static __always_inline int emit_path_event(__u32 action, const char *path)
{
    if (!action)
        return 0;
    struct event_t *e = event_alloc(action);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = action;
    __builtin_memcpy(e->filename, path, sizeof(e->filename));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Tracepoint entry for user-supplied paths (open family). Attempt-based
 * classes always run here; resolved-path classes run here only when the
 * LSM hook is not attached (see classify_resolved_path). */
static __always_inline int handle_open_path(const char *filename, __u64 flags)
{
    __u32 zero = 0;
    __u32 *lsm = bpf_map_lookup_elem(&file_hook_lsm, &zero);
    int lsm_active = (lsm && *lsm) != 0;
    char path[MAX_FILENAME_LEN] = {};
    if (bpf_probe_read_user_str(path, sizeof(path), filename) < 0)
        return 0;
    __u32 action = classify_attempt_path(path);
    if (!action && !lsm_active)
        action = classify_resolved_path(path, flags);
    return emit_path_event(action, path);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter_openat *ctx)
{
    return handle_open_path(ctx->filename, (__u64)ctx->flags);
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter_open *ctx)
{
    return handle_open_path(ctx->filename, (__u64)ctx->flags);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter_openat2 *ctx)
{
    struct open_how_u {
        __u64 flags;
        __u64 mode;
        __u64 resolve;
    } how = {};
    bpf_probe_read_user(&how, sizeof(how), ctx->how);
    return handle_open_path(ctx->filename, how.flags);
}

/* ================== Process execution ================== */

struct trace_event_raw_sys_enter_execve {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter_execve *ctx)
{
    struct event_t *e = event_alloc(ACTION_PROCESS_EXECUTION);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_PROCESS_EXECUTION;
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================== Network connection ================== */

struct trace_event_raw_sys_enter_connect {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    __s64 fd;
    struct sockaddr *uservaddr;
    __s64 addrlen;
};

struct sockaddr_in_min {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
};

struct sockaddr_in6_min {
    __u16 sin6_family;
    __u16 sin6_port;
    __u32 sin6_flowinfo;
    __u8  sin6_addr[16];
};

#define AF_INET_VAL  2
#define AF_INET6_VAL 10

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter_connect *ctx)
{
    /* Read the family first, then the full sockaddr of the right size:
     * reading in6-sized from a v4 sockaddr could fault past its page. */
    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), ctx->uservaddr) != 0)
        return 0;

    if (family == AF_INET_VAL) {
        struct sockaddr_in_min a4 = {};
        if (bpf_probe_read_user(&a4, sizeof(a4), ctx->uservaddr) != 0)
            return 0;
        struct event_t *e = event_alloc(ACTION_NETWORK_CONNECTION);
        if (!e) return 0;
        event_fill_common(e);
        e->action_id = ACTION_NETWORK_CONNECTION;
        __builtin_memcpy(e->dest_ip, &a4.sin_addr, 4);
        e->dest_port = ((a4.sin_port & 0xff) << 8) | (a4.sin_port >> 8);
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    if (family == AF_INET6_VAL) {
        struct sockaddr_in6_min a6 = {};
        if (bpf_probe_read_user(&a6, sizeof(a6), ctx->uservaddr) != 0)
            return 0;
        struct event_t *e = event_alloc(ACTION_NETWORK_CONNECTION);
        if (!e) return 0;
        event_fill_common(e);
        e->action_id = ACTION_NETWORK_CONNECTION;
        __builtin_memcpy(e->dest_ip, &a6.sin6_addr, 16);
        e->dest_port = ((a6.sin6_port & 0xff) << 8) | (a6.sin6_port >> 8);
        bpf_ringbuf_submit(e, 0);
        return 0;
    }

    return 0;
}

/* ================== ptrace ================== */

struct trace_event_raw_sys_enter_ptrace {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    long int request;
    long int pid;
    unsigned long addr;
    unsigned long data;
};

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter_ptrace *ctx)
{
    struct event_t *e = event_alloc(ACTION_PROCESS_INJECTION);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_PROCESS_INJECTION;
    e->aux_u16 = (__u16)ctx->request;
    e->aux_u32 = (__u32)ctx->pid;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================== Log tampering ================== */

struct trace_event_raw_sys_enter_unlinkat {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    __s64 dfd;
    const char *pathname;
    __s64 flag;
};

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter_unlinkat *ctx)
{
    char path[MAX_FILENAME_LEN] = {};
    if (bpf_probe_read_user_str(path, sizeof(path), ctx->pathname) < 0)
        return 0;
    if (!MATCH_STR(path, "/var/log/ebpf_edr"))
        return 0;

    struct event_t *e = event_alloc(ACTION_LOG_TAMPERING);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_LOG_TAMPERING;
    __builtin_memcpy(e->filename, path, sizeof(e->filename));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================== NEW: eBPF tampering ================== */

struct trace_event_raw_sys_enter_bpf {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    int cmd;
};

/* BPF cmd values we care about:
 *   0  = BPF_MAP_CREATE
 *   5  = BPF_PROG_LOAD
 *   8  = BPF_PROG_ATTACH
 *   28 = BPF_LINK_CREATE
 */
#define BPF_CMD_MAP_CREATE   0
#define BPF_CMD_PROG_LOAD    5
#define BPF_CMD_PROG_ATTACH  8
#define BPF_CMD_LINK_CREATE  28

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter_bpf *ctx)
{
    int cmd = ctx->cmd;
    if (cmd != BPF_CMD_MAP_CREATE &&
        cmd != BPF_CMD_PROG_LOAD &&
        cmd != BPF_CMD_PROG_ATTACH &&
        cmd != BPF_CMD_LINK_CREATE)
        return 0;

    struct event_t *e = event_alloc(ACTION_EBPF_TAMPERING);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_EBPF_TAMPERING;
    e->aux_u32 = (__u32)cmd;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================== NEW: perf_event_open ================== */

struct trace_event_raw_sys_enter_perf_event_open {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    void *attr;
    int pid;
    int cpu;
    int group_fd;
    unsigned long flags;
};

SEC("tracepoint/syscalls/sys_enter_perf_event_open")
int trace_perf_event_open(struct trace_event_raw_sys_enter_perf_event_open *ctx)
{
    struct event_t *e = event_alloc(ACTION_PERF_EVENT_OPEN);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_PERF_EVENT_OPEN;
    e->aux_u32 = (__u32)ctx->pid;
    e->aux_u16 = (__u16)ctx->cpu;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================== NEW: suspicious mount ================== */

struct trace_event_raw_sys_enter_mount {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    const char *dev_name;
    const char *dir_name;
    const char *type;
    unsigned long flags;
    void *data;
};

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_mount(struct trace_event_raw_sys_enter_mount *ctx)
{
    struct event_t *e = event_alloc(ACTION_SUSPICIOUS_MOUNT);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_SUSPICIOUS_MOUNT;
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), ctx->dir_name);
    e->aux_u64 = (__u64)ctx->flags;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================== NEW: namespace switch ================== */

struct trace_event_raw_sys_enter_setns {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    int fd;
    int nstype;
};

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter_setns *ctx)
{
    struct event_t *e = event_alloc(ACTION_NAMESPACE_SWITCH);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_NAMESPACE_SWITCH;
    e->aux_u16 = (__u16)ctx->nstype;
    e->aux_u32 = (__u32)ctx->fd;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================== NEW: chroot ================== */

struct trace_event_raw_sys_enter_chroot {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    const char *filename;
};

SEC("tracepoint/syscalls/sys_enter_chroot")
int trace_chroot(struct trace_event_raw_sys_enter_chroot *ctx)
{
    struct event_t *e = event_alloc(ACTION_CHROOT_ESCAPE);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_CHROOT_ESCAPE;
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================== NEW: executable memory (W^X) ================== */

struct trace_event_raw_sys_enter_mprotect {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    unsigned long start;
    unsigned long len;
    unsigned long prot;
};

#define PROT_EXEC_VAL 0x4

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter_mprotect *ctx)
{
    if (!(ctx->prot & PROT_EXEC_VAL))
        return 0;

    struct event_t *e = event_alloc(ACTION_EXECUTABLE_MEMORY);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_EXECUTABLE_MEMORY;
    e->aux_u64 = (__u64)ctx->start;
    e->aux_u32 = (__u32)ctx->prot;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================== NEW: log tampering v2 (Phase D) ================== */
/* unlinkat only caught deletion; wiping or moving the audit log via
 * truncate / rename / renameat / renameat2 evaded detection. Write-intent
 * opens of the log are caught by classify_resolved_path above. */

struct trace_event_raw_sys_enter_truncate {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    const char *path;
    __s64 length;
};

static __always_inline int handle_log_path_only(const char *pathname, __u64 aux)
{
    char path[MAX_FILENAME_LEN] = {};
    if (bpf_probe_read_user_str(path, sizeof(path), pathname) < 0)
        return 0;
    if (!is_edr_log_path(path))
        return 0;
    struct event_t *e = event_alloc(ACTION_LOG_TAMPERING);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_LOG_TAMPERING;
    __builtin_memcpy(e->filename, path, sizeof(e->filename));
    e->aux_u64 = aux;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_truncate(struct trace_event_raw_sys_enter_truncate *ctx)
{
    return handle_log_path_only(ctx->path, (__u64)ctx->length);
}

struct trace_event_raw_sys_enter_rename {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    const char *oldname;
    const char *newname;
};

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter_rename *ctx)
{
    return handle_log_path_only(ctx->oldname, 0);
}

struct trace_event_raw_sys_enter_renameat {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    __s64 olddfd;
    const char *oldname;
    __s64 newdfd;
    const char *newname;
};

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter_renameat *ctx)
{
    return handle_log_path_only(ctx->oldname, 0);
}

struct trace_event_raw_sys_enter_renameat2 {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    __s64 olddfd;
    const char *oldname;
    __s64 newdfd;
    const char *newname;
    __u32 flags;
};

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter_renameat2 *ctx)
{
    return handle_log_path_only(ctx->oldname, (__u64)ctx->flags);
}

/* ================== NEW: fileless execution & modules (Phase D) ======= */

struct trace_event_raw_sys_enter_memfd_create {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    const char *name;
    __u32 flags;
};

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_memfd_create(struct trace_event_raw_sys_enter_memfd_create *ctx)
{
    struct event_t *e = event_alloc(ACTION_MEMFD_CREATE);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_MEMFD_CREATE;
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), ctx->name);
    e->aux_u32 = ctx->flags;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct trace_event_raw_sys_enter_execveat {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    __s64 dfd;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
    __s64 flags;
};

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter_execveat *ctx)
{
    struct event_t *e = event_alloc(ACTION_EXECVEAT);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_EXECVEAT;
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), ctx->filename);
    e->aux_u32 = (__u32)ctx->flags;
    e->aux_u16 = (__u16)ctx->dfd;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct trace_event_raw_sys_enter_init_module {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    void *umod;
    __s64 len;
    const char *uargs;
};

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter_init_module *ctx)
{
    struct event_t *e = event_alloc(ACTION_KERNEL_MODULE_LOAD);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_KERNEL_MODULE_LOAD;
    e->aux_u64 = (__u64)ctx->len;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct trace_event_raw_sys_enter_finit_module {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __u8  common_pid;
    long int id;
    __s64 fd;
    const char *uargs;
    __s64 flags;
};

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_finit_module(struct trace_event_raw_sys_enter_finit_module *ctx)
{
    struct event_t *e = event_alloc(ACTION_KERNEL_MODULE_LOAD);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_KERNEL_MODULE_LOAD;
    e->aux_u64 = (__u64)ctx->fd;
    e->aux_u32 = (__u32)ctx->flags;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ================== NEW: BPF LSM file_open (Phase D) ================== */
/* Fires on every file open AFTER path resolution via bpf_d_path — the
 * resolved kernel path closes the io_uring open bypass and the
 * user-space filename race in one architectural step. Requires kernel
 * with CONFIG_BPF_LSM and bpf in the active LSM list; userspace deletes
 * this section before load when unavailable (see main.go).
 * Scope: resolved-path classes only (see classify_resolved_path) —
 * attempt-based classes (canary, release_agent) stay on the tracepoints,
 * because this hook never fires for opens that fail resolution.
 * AUDIT-ONLY: always returns 0 — this sensor never denies an open. */
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    char path[MAX_FILENAME_LEN] = {};
    long n = bpf_d_path(&file->f_path, path, sizeof(path));
    if (n < 0)
        return 0;
    __u32 fflags = 0;
    if (bpf_core_read(&fflags, sizeof(fflags), &file->f_flags) != 0)
        return 0;
    emit_path_event(classify_resolved_path(path, (__u64)fflags), path);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
