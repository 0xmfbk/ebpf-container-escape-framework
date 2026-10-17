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

/* Indexed by action_id. 1 = emit, 0 = drop. Populated by userspace before
 * attach. ARRAY so lookups are O(1) and cannot fail for valid keys. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u32);
} action_enabled SEC(".maps");

/* ================== Helpers ================== */

static __always_inline __u32 current_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return 0;
    struct task_struct *parent = NULL;
    if (bpf_core_read(&parent, sizeof(parent), &task->real_parent))
        return 0;
    if (!parent)
        return 0;
    __u32 ppid = 0;
    if (bpf_core_read(&ppid, sizeof(ppid), &parent->tgid))
        return 0;
    return ppid;
}

static __always_inline __u64 current_start_time_ns(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return 0;
    __u64 t = 0;
    if (bpf_core_read(&t, sizeof(t), &task->start_boottime))
        return 0;
    return t;
}

static __always_inline int is_filtered(void)
{
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
    if (is_filtered())
        return NULL;
    __u32 *en = bpf_map_lookup_elem(&action_enabled, &action_id);
    if (!en || !*en)
        return NULL;
    return bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
}

static __always_inline void event_fill_common(struct event_t *e)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->version       = EVENT_VERSION;
    e->cgroup_id     = bpf_get_current_cgroup_id();
    e->pid           = (__u32)(pid_tgid >> 32);
    e->ppid          = current_ppid();
    e->uid           = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->start_time_ns = current_start_time_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline int is_shadow_path(const char *p)
{
    return MATCH_STR(p, "/etc/shadow");
}

static __always_inline int is_docker_sock_path(const char *p)
{
    return MATCH_STR(p, "/var/run/docker.sock");
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

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter_openat *ctx)
{
    char path[MAX_FILENAME_LEN] = {};
    if (bpf_probe_read_user_str(path, sizeof(path), ctx->filename) < 0)
        return 0;
    if (!is_shadow_path(path) && !is_docker_sock_path(path))
        return 0;

    struct event_t *e = event_alloc(ACTION_SENSITIVE_FILE_ACCESS);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_SENSITIVE_FILE_ACCESS;
    __builtin_memcpy(e->filename, path, sizeof(e->filename));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

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

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter_open *ctx)
{
    char path[MAX_FILENAME_LEN] = {};
    if (bpf_probe_read_user_str(path, sizeof(path), ctx->filename) < 0)
        return 0;
    if (!is_shadow_path(path) && !is_docker_sock_path(path))
        return 0;

    struct event_t *e = event_alloc(ACTION_SENSITIVE_FILE_ACCESS);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_SENSITIVE_FILE_ACCESS;
    __builtin_memcpy(e->filename, path, sizeof(e->filename));
    bpf_ringbuf_submit(e, 0);
    return 0;
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

#define AF_INET_VAL 2

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter_connect *ctx)
{
    struct sockaddr_in_min addr = {};
    if (bpf_probe_read_user(&addr, sizeof(addr), ctx->uservaddr) != 0)
        return 0;
    if (addr.sin_family != AF_INET_VAL)
        return 0;

    struct event_t *e = event_alloc(ACTION_NETWORK_CONNECTION);
    if (!e) return 0;
    event_fill_common(e);
    e->action_id = ACTION_NETWORK_CONNECTION;
    __builtin_memcpy(e->dest_ip, &addr.sin_addr, 4);
    e->dest_port = ((addr.sin_port & 0xff) << 8) | (addr.sin_port >> 8);
    bpf_ringbuf_submit(e, 0);
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

char LICENSE[] SEC("license") = "GPL";
