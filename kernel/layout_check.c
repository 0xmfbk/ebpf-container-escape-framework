/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t  __u8;

#include "../common/common.h"

int main(void)
{
    printf("VERSION=%d\n", EVENT_VERSION);
    printf("SIZE=%zu\n", sizeof(struct event_t));
    printf("OFF_cgroup_id=%zu\n",     offsetof(struct event_t, cgroup_id));
    printf("OFF_start_time_ns=%zu\n", offsetof(struct event_t, start_time_ns));
    printf("OFF_version=%zu\n",       offsetof(struct event_t, version));
    printf("OFF_action_id=%zu\n",     offsetof(struct event_t, action_id));
    printf("OFF_pid=%zu\n",           offsetof(struct event_t, pid));
    printf("OFF_ppid=%zu\n",          offsetof(struct event_t, ppid));
    printf("OFF_uid=%zu\n",           offsetof(struct event_t, uid));
    printf("OFF_flags=%zu\n",         offsetof(struct event_t, flags));
    printf("OFF_comm=%zu\n",          offsetof(struct event_t, comm));
    printf("OFF_filename=%zu\n",      offsetof(struct event_t, filename));
    printf("OFF_dest_ip=%zu\n",       offsetof(struct event_t, dest_ip));
    printf("OFF_dest_port=%zu\n",     offsetof(struct event_t, dest_port));
    printf("OFF_aux_u16=%zu\n",       offsetof(struct event_t, aux_u16));
    printf("OFF_aux_u64=%zu\n",       offsetof(struct event_t, aux_u64));
    printf("OFF_aux_u32=%zu\n",       offsetof(struct event_t, aux_u32));
    return 0;
}
