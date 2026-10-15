#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../common/common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} enforcement_map SEC(".maps");

static __always_inline void enforce_action(void *ctx, struct event_t *e) {
    __u32 key = 0;
    __u32 *enforce_mode = bpf_map_lookup_elem(&enforcement_map, &key);
    
    if (enforce_mode && *enforce_mode == 1) {
        bpf_send_signal(9);
    }
}

SEC("kprobe/__x64_sys_unshare")
int BPF_KPROBE(trace_unshare, int flags) {
    struct event_t *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memcpy(e->action, "Container_Namespace_Unshare", 30);

    enforce_action(ctx, e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_pivot_root")
int BPF_KPROBE(trace_pivot_root) {
    struct event_t *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->action, "Container_Pivot_Root_Escape", 30);

    enforce_action(ctx, e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct trace_event_raw_sys_enter_openat {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __u8 common_pid;
    long int id;
    __s64 dfd;
    const char *filename;
    __s64 flags;
    __s64 mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter_openat *ctx) {
    struct event_t *e;
    char path[64] = {0};

    bpf_probe_read_user_str(path, sizeof(path), ctx->filename);

    int is_shadow = (__builtin_memcmp(path, "/etc/shadow", 11) == 0);
    int is_docker_sock = (__builtin_memcmp(path, "/var/run/docker.sock", 20) == 0);

    if (!is_shadow && !is_docker_sock) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memcpy(e->action, "Sensitive_File_Access", 30);
    __builtin_memcpy(e->filename, path, sizeof(e->filename));

    enforce_action(ctx, e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct trace_event_raw_sys_enter_open {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __u8 common_pid;
    long int id;
    const char *filename;
    __s64 flags;
    __s64 mode;
};

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter_open *ctx) {
    struct event_t *e;
    char path[64] = {0};

    bpf_probe_read_user_str(path, sizeof(path), ctx->filename);

    int is_shadow = (__builtin_memcmp(path, "/etc/shadow", 11) == 0);
    int is_docker_sock = (__builtin_memcmp(path, "/var/run/docker.sock", 20) == 0);

    if (!is_shadow && !is_docker_sock) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memcpy(e->action, "Sensitive_File_Access", 30);
    __builtin_memcpy(e->filename, path, sizeof(e->filename));

    enforce_action(ctx, e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct trace_event_raw_sys_enter_execve {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __u8 common_pid;
    long int id;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    struct event_t *e;
    char path[64] = {0};

    bpf_probe_read_user_str(path, sizeof(path), ctx->filename);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memcpy(e->action, "Process_Execution", 20);
    __builtin_memcpy(e->filename, path, sizeof(e->filename));

    enforce_action(ctx, e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

struct trace_event_raw_sys_enter_connect {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __u8 common_pid;
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
int trace_connect(struct trace_event_raw_sys_enter_connect *ctx) {
    struct event_t *e;
    struct sockaddr_in_min addr = {};

    if (bpf_probe_read_user(&addr, sizeof(addr), ctx->uservaddr) != 0) {
        return 0;
    }

    if (addr.sin_family != AF_INET_VAL) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memcpy(e->action, "Network_Connection", 20);

    __builtin_memcpy(e->dest_ip, &addr.sin_addr, 4);
    e->dest_port = ((addr.sin_port & 0xff) << 8) | (addr.sin_port >> 8);

    enforce_action(ctx, e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter_openat *ctx) {
    struct event_t *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memcpy(e->action, "Process_Injection", 20);

    enforce_action(ctx, e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter_openat *ctx) {
    struct event_t *e;
    char path[64] = {0};

    bpf_probe_read_user_str(path, sizeof(path), ctx->filename);

    int is_edr_log = (__builtin_memcmp(path, "/var/log/ebpf_edr", 15) == 0);
    if (!is_edr_log) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __builtin_memcpy(e->action, "Log_Tampering", 20);
    __builtin_memcpy(e->filename, path, sizeof(e->filename));

    enforce_action(ctx, e);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
