/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EBPF_EDR_COMMON_H
#define __EBPF_EDR_COMMON_H

#define EVENT_VERSION 3

#define MAX_COMM_LEN     16
#define MAX_FILENAME_LEN 128
#define MAX_DEST_IP_LEN  4

enum event_action {
    ACTION_UNKNOWN                     = 0,
    ACTION_CONTAINER_NAMESPACE_UNSHARE = 1,
    ACTION_CONTAINER_PIVOT_ROOT_ESCAPE = 2,
    ACTION_SENSITIVE_FILE_ACCESS       = 3,
    ACTION_PROCESS_EXECUTION           = 4,
    ACTION_NETWORK_CONNECTION          = 5,
    ACTION_PROCESS_INJECTION           = 6,
    ACTION_LOG_TAMPERING               = 7,
    ACTION_EBPF_TAMPERING              = 8,
    ACTION_PERF_EVENT_OPEN             = 9,
    ACTION_SUSPICIOUS_MOUNT            = 10,
    ACTION_NAMESPACE_SWITCH            = 11,
    ACTION_CHROOT_ESCAPE               = 12,
    ACTION_EXECUTABLE_MEMORY           = 13,
    ACTION__MAX                        = 14,
};

/* Event flags (bitfield in event_t.flags). */
#define EVENT_FLAG_IS_CONTAINER (1U << 0)
#define EVENT_FLAG_ENFORCED     (1U << 1)
#define EVENT_FLAG_RATE_LIMITED (1U << 2)

/*
 * Wire format v3. 208 bytes, natural alignment. New fields at the end:
 *   aux_u16  — small auxiliary (bpf cmd, mprotect prot, setns nstype)
 *   aux_u64  — larger auxiliary (mmap address, mount flags)
 *   aux_u32  — mid-size auxiliary (bpf prog_type, perf pid)
 */
struct event_t {
    __u64 cgroup_id;                  /*   0 */
    __u64 start_time_ns;              /*   8 */
    __u32 version;                    /*  16 */
    __u32 action_id;                  /*  20 */
    __u32 pid;                        /*  24 */
    __u32 ppid;                       /*  28 */
    __u32 uid;                        /*  32 */
    __u32 flags;                      /*  36 */
    __u8  comm[MAX_COMM_LEN];         /*  40 */
    __u8  filename[MAX_FILENAME_LEN]; /*  56 */
    __u8  dest_ip[MAX_DEST_IP_LEN];   /* 184 */
    __u16 dest_port;                  /* 188 */
    __u16 aux_u16;                    /* 190 */
    __u64 aux_u64;                    /* 192 */
    __u32 aux_u32;                    /* 200 */
} __attribute__((aligned(8)));

_Static_assert(sizeof(struct event_t) == 208, "event_t layout drift v3");

#endif /* __EBPF_EDR_COMMON_H */
