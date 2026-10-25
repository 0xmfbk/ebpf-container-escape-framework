/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EBPF_EDR_COMMON_H
#define __EBPF_EDR_COMMON_H

#define EVENT_VERSION 4

#define MAX_COMM_LEN     16
#define MAX_FILENAME_LEN 128
/* 16 bytes: full IPv6 address; IPv4 events zero-fill bytes 4..15 and
 * userspace formats them as dotted quad. */
#define MAX_DEST_IP_LEN  16

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
    ACTION_CORE_PATTERN_MODIFICATION   = 14,
    ACTION_CGROUP_RELEASE_AGENT        = 15,
    ACTION_CANARY_TRIGGERED            = 16,
    ACTION_MEMFD_CREATE                = 17,
    ACTION_EXECVEAT                    = 18,
    ACTION_KERNEL_MODULE_LOAD          = 19,
    ACTION__MAX                        = 20,
};

/* Event flags (bitfield in event_t.flags). */
#define EVENT_FLAG_IS_CONTAINER (1U << 0)
#define EVENT_FLAG_ENFORCED     (1U << 1)
#define EVENT_FLAG_RATE_LIMITED (1U << 2)

/*
 * Wire format v4. 224 bytes, natural alignment. Changes from v3:
 *   - dest_ip widened 4 -> 16 bytes (IPv6 support)
 *   - dest_port/aux_u16/aux_u64/aux_u32 shifted accordingly
 * Kernel zeroes the record on reserve; readers must check version==4.
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
    __u16 dest_port;                  /* 200 */
    __u16 aux_u16;                    /* 202 */
    __u64 aux_u64;                    /* 208 */
    __u32 aux_u32;                    /* 216 */
    /* 4 bytes tail padding to 8-byte alignment */
} __attribute__((aligned(8)));

_Static_assert(sizeof(struct event_t) == 224, "event_t layout drift v4");

#endif /* __EBPF_EDR_COMMON_H */
