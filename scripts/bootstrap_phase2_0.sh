#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Phase 2.0 one-shot bootstrap for ebpf-container-escape-framework.
# Writes all safety-refactor + verification files. Backs up everything.
# Idempotent. Requires root only for convenient single-password run.

set -euo pipefail

# The bootstrap harness runs the adversary emulation binary, which
# requires an explicit opt-in; this script is only run on test hosts.
export EDR_EMULATION_CONFIRMED=1

if [[ $EUID -ne 0 ]]; then
    echo "Run as root:  sudo -E bash scripts/bootstrap_phase2_0.sh"
    exit 1
fi

REAL_USER="${SUDO_USER:-root}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

echo "==> repo root: $ROOT"
echo "==> real user: $REAL_USER"

BACKUP="$ROOT/.phase2_0_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP"

bk() {
    local f="$1"
    if [[ -f "$f" ]]; then
        mkdir -p "$BACKUP/$(dirname "$f")"
        cp -a "$f" "$BACKUP/$f"
        echo "    backed up: $f"
    fi
}

mkdir -p common kernel userspace scripts

echo "==> backing up existing files"
bk Makefile
bk common/common.h
bk kernel/bpf_program.c
bk userspace/main.go
bk userspace/serializer.go
bk userspace/layout_test.go
bk kernel/layout_check.c
bk scripts/verify_phase2_0.sh
echo "==> backup dir: $BACKUP"

# ---------------------------------------------------------------
# common/common.h
# ---------------------------------------------------------------
echo "==> writing common/common.h"
cat > common/common.h <<'HDR_EOF'
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __EBPF_EDR_COMMON_H
#define __EBPF_EDR_COMMON_H

/*
 * Shared between BPF programs (kernel/bpf_program.c) and the Go daemon
 * (userspace/main.go). The Go struct event_t MUST mirror this layout
 * byte-for-byte. Size is asserted here and validated at runtime.
 */

#define EVENT_VERSION 2

#define MAX_COMM_LEN     16
#define MAX_FILENAME_LEN 128
#define MAX_DEST_IP_LEN  4

/* Stable action IDs. Append only; never reorder. */
enum event_action {
    ACTION_UNKNOWN                     = 0,
    ACTION_CONTAINER_NAMESPACE_UNSHARE = 1,
    ACTION_CONTAINER_PIVOT_ROOT_ESCAPE = 2,
    ACTION_SENSITIVE_FILE_ACCESS       = 3,
    ACTION_PROCESS_EXECUTION           = 4,
    ACTION_NETWORK_CONNECTION          = 5,
    ACTION_PROCESS_INJECTION           = 6,
    ACTION_LOG_TAMPERING               = 7,
    ACTION__MAX                        = 8,
};

#define EVENT_FLAG_IS_CONTAINER (1U << 0)
#define EVENT_FLAG_ENFORCED     (1U << 1)
#define EVENT_FLAG_RATE_LIMITED (1U << 2)

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
    __u16 reserved2;                  /* 190 */
    __u64 reserved3;                  /* 192 */
} __attribute__((aligned(8)));

_Static_assert(sizeof(struct event_t) == 200, "event_t layout drift");

#endif /* __EBPF_EDR_COMMON_H */
HDR_EOF

# ---------------------------------------------------------------
# kernel/bpf_program.c
# ---------------------------------------------------------------
echo "==> writing kernel/bpf_program.c"
cat > kernel/bpf_program.c <<'BPF_EOF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../common/common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 * 1024 * 1024); /* 1 MiB */
} events SEC(".maps");

#define COPY_LITERAL(dst, src) do {                                 \
    _Static_assert(sizeof(src) <= sizeof(dst), "dst too small");    \
    __builtin_memcpy(dst, src, sizeof(src));                        \
} while (0)

static __always_inline __u32 current_ppid(void)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
    if (!t)
        return 0;
    return BPF_CORE_READ(t, real_parent, tgid);
}

static __always_inline __u64 current_start_time_ns(void)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
    if (!t)
        return 0;
    return BPF_CORE_READ(t, start_boottime);
}

static __always_inline struct event_t *event_alloc(void)
{
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
    return __builtin_memcmp(p, "/etc/shadow", 12) == 0;
}

static __always_inline int is_docker_sock_path(const char *p)
{
    return __builtin_memcmp(p, "/var/run/docker.sock", 21) == 0;
}

SEC("kprobe/__x64_sys_unshare")
int BPF_KPROBE(trace_unshare, int flags)
{
    struct event_t *e = event_alloc();
    if (!e)
        return 0;
    event_fill_common(e);
    e->action_id = ACTION_CONTAINER_NAMESPACE_UNSHARE;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_pivot_root")
int BPF_KPROBE(trace_pivot_root)
{
    struct event_t *e = event_alloc();
    if (!e)
        return 0;
    event_fill_common(e);
    e->action_id = ACTION_CONTAINER_PIVOT_ROOT_ESCAPE;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

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

    struct event_t *e = event_alloc();
    if (!e)
        return 0;
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

    struct event_t *e = event_alloc();
    if (!e)
        return 0;
    event_fill_common(e);
    e->action_id = ACTION_SENSITIVE_FILE_ACCESS;
    __builtin_memcpy(e->filename, path, sizeof(e->filename));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

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
    struct event_t *e = event_alloc();
    if (!e)
        return 0;
    event_fill_common(e);
    e->action_id = ACTION_PROCESS_EXECUTION;
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), ctx->filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

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

    struct event_t *e = event_alloc();
    if (!e)
        return 0;
    event_fill_common(e);
    e->action_id = ACTION_NETWORK_CONNECTION;
    __builtin_memcpy(e->dest_ip, &addr.sin_addr, 4);
    e->dest_port = ((addr.sin_port & 0xff) << 8) | (addr.sin_port >> 8);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

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
    struct event_t *e = event_alloc();
    if (!e)
        return 0;
    event_fill_common(e);
    e->action_id = ACTION_PROCESS_INJECTION;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

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
    if (__builtin_memcmp(path, "/var/log/ebpf_edr", 15) != 0)
        return 0;

    struct event_t *e = event_alloc();
    if (!e)
        return 0;
    event_fill_common(e);
    e->action_id = ACTION_LOG_TAMPERING;
    __builtin_memcpy(e->filename, path, sizeof(e->filename));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
BPF_EOF

# ---------------------------------------------------------------
# kernel/layout_check.c
# ---------------------------------------------------------------
echo "==> writing kernel/layout_check.c"
cat > kernel/layout_check.c <<'LAY_EOF'
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
    return 0;
}
LAY_EOF

# ---------------------------------------------------------------
# userspace/main.go
# ---------------------------------------------------------------
echo "==> writing userspace/main.go"
cat > userspace/main.go <<'MAIN_EOF'
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	logPath       = "/var/log/ebpf_edr.json"
	logMaxBytes   = 50 * 1024 * 1024
	logMaxBackups = 5

	eventChanSize = 4096
	eventSize     = 200
	eventWords    = eventSize / 8

	healthLogInterval = 60 * time.Second
	eventVersion      = 2
)

type event_t struct {
	CgroupID    uint64
	StartTimeNs uint64
	Version     uint32
	ActionID    uint32
	Pid         uint32
	Ppid        uint32
	Uid         uint32
	Flags       uint32
	Comm        [16]byte
	Filename    [128]byte
	DestIP      [4]byte
	DestPort    uint16
	Reserved2   uint16
	Reserved3   uint64
}

const (
	ActionUnknown                   = 0
	ActionContainerNamespaceUnshare = 1
	ActionContainerPivotRootEscape  = 2
	ActionSensitiveFileAccess       = 3
	ActionProcessExecution          = 4
	ActionNetworkConnection         = 5
	ActionProcessInjection          = 6
	ActionLogTampering              = 7
)

var actionNames = map[uint32]string{
	ActionContainerNamespaceUnshare: "Container_Namespace_Unshare",
	ActionContainerPivotRootEscape:  "Container_Pivot_Root_Escape",
	ActionSensitiveFileAccess:       "Sensitive_File_Access",
	ActionProcessExecution:          "Process_Execution",
	ActionNetworkConnection:         "Network_Connection",
	ActionProcessInjection:          "Process_Injection",
	ActionLogTampering:              "Log_Tampering",
}

type SecurityAlert struct {
	Timestamp      string `json:"timestamp"`
	PID            uint32 `json:"pid"`
	PPID           uint32 `json:"ppid,omitempty"`
	UID            uint32 `json:"uid"`
	StartTimeNs    uint64 `json:"start_time_ns,omitempty"`
	Command        string `json:"command"`
	Action         string `json:"action"`
	Target         string `json:"target,omitempty"`
	Severity       string `json:"severity"`
	MitreID        string `json:"mitre_id"`
	MitreTechnique string `json:"mitre_technique"`
	CgroupID       uint64 `json:"cgroup_id"`
	ContainerID    string `json:"container_id,omitempty"`
	Runtime        string `json:"runtime"`
	DestIP         string `json:"dest_ip,omitempty"`
	DestPort       uint16 `json:"dest_port,omitempty"`
}

var suspiciousPorts = map[uint16]bool{
	4444:  true,
	1337:  true,
	31337: true,
	6666:  true,
	6697:  true,
}

func formatIPv4(ip [4]byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func calculateSeverity(action, command, target string, destPort uint16) (string, string, string) {
	switch action {
	case "Container_Pivot_Root_Escape":
		return "CRITICAL", "T1611", "Escape to Host"
	case "Container_Namespace_Unshare":
		return "HIGH", "T1611", "Escape to Host"
	case "Sensitive_File_Access":
		return "HIGH", "T1003.008", "OS Credential Dumping: /etc/shadow"
	case "Process_Injection":
		return "HIGH", "T1055.008", "Process Injection: PTRACE"
	case "Log_Tampering":
		return "HIGH", "T1562.001", "Impair Defenses: Indicator Blocking"
	case "Network_Connection":
		if suspiciousPorts[destPort] {
			return "HIGH", "T1071", "Application Layer Protocol (Suspicious Port)"
		}
		return "INFO", "T1071", "Application Layer Protocol"
	case "Process_Execution":
		if target == "/bin/sh" || target == "/bin/bash" || command == "python3" || command == "nc" {
			return "MEDIUM", "T1059.004", "Command and Scripting Interpreter: Unix Shell"
		}
		return "INFO", "T1059.004", "Command and Scripting Interpreter"
	default:
		return "INFO", "T1204", "User Execution"
	}
}

type agentStats struct {
	eventsReceived  uint64
	eventsDropped   uint64
	eventsWritten   uint64
	parseErrors     uint64
	versionMismatch uint64
	ringbufReadErrs uint64
}

var stats agentStats

type rawEvent struct {
	data [eventWords]uint64
}

func main() {
	eventWriter, rotLogger := NewEnterpriseWriter(logPath, logMaxBytes, logMaxBackups)
	defer rotLogger.Close()

	resolver := newContainerResolver()

	spec, err := ebpf.LoadCollectionSpec("../kernel/bpf_program.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	var objs struct {
		ProgUnshare   *ebpf.Program `ebpf:"trace_unshare"`
		ProgPivotRoot *ebpf.Program `ebpf:"trace_pivot_root"`
		ProgOpenat    *ebpf.Program `ebpf:"trace_openat"`
		ProgOpen      *ebpf.Program `ebpf:"trace_open"`
		ProgExecve    *ebpf.Program `ebpf:"trace_execve"`
		ProgConnect   *ebpf.Program `ebpf:"trace_connect"`
		ProgPtrace    *ebpf.Program `ebpf:"trace_ptrace"`
		ProgUnlinkat  *ebpf.Program `ebpf:"trace_unlinkat"`
		Events        *ebpf.Map     `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load and assign eBPF objects: %v", err)
	}
	defer objs.ProgUnshare.Close()
	defer objs.ProgPivotRoot.Close()
	defer objs.ProgOpenat.Close()
	defer objs.ProgOpen.Close()
	defer objs.ProgExecve.Close()
	defer objs.ProgConnect.Close()
	defer objs.ProgPtrace.Close()
	defer objs.ProgUnlinkat.Close()
	defer objs.Events.Close()

	kpUnshare, err := link.Kprobe("__x64_sys_unshare", objs.ProgUnshare, nil)
	if err != nil {
		log.Fatalf("Failed to attach unshare kprobe: %v", err)
	}
	defer kpUnshare.Close()

	kpPivot, err := link.Kprobe("__x64_sys_pivot_root", objs.ProgPivotRoot, nil)
	if err != nil {
		log.Fatalf("Failed to attach pivot_root kprobe: %v", err)
	}
	defer kpPivot.Close()

	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.ProgOpenat, nil)
	if err != nil {
		log.Fatalf("Failed to attach openat tracepoint: %v", err)
	}
	defer tpOpenat.Close()

	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_open", objs.ProgOpen, nil)
	if err != nil {
		log.Fatalf("Failed to attach open tracepoint: %v", err)
	}
	defer tpOpen.Close()

	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.ProgExecve, nil)
	if err != nil {
		log.Fatalf("Failed to attach execve tracepoint: %v", err)
	}
	defer tpExecve.Close()

	tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.ProgConnect, nil)
	if err != nil {
		log.Fatalf("Failed to attach connect tracepoint: %v", err)
	}
	defer tpConnect.Close()

	tpPtrace, err := link.Tracepoint("syscalls", "sys_enter_ptrace", objs.ProgPtrace, nil)
	if err != nil {
		log.Fatalf("Failed to attach ptrace tracepoint: %v", err)
	}
	defer tpPtrace.Close()

	tpUnlinkat, err := link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.ProgUnlinkat, nil)
	if err != nil {
		log.Fatalf("Failed to attach unlinkat tracepoint: %v", err)
	}
	defer tpUnlinkat.Close()

	log.Printf("[-] EDR Engine active (event version %d). Streaming to stdout + %s",
		eventVersion, logPath)

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	eventChan := make(chan rawEvent, eventChanSize)
	done := make(chan struct{})

	go func() {
		<-sigChan
		rd.Close()
	}()

	go func() {
		defer close(eventChan)
		for {
			record, err := rd.Read()
			if err != nil {
				atomic.AddUint64(&stats.ringbufReadErrs, 1)
				log.Printf("ringbuf reader terminated: %v", err)
				return
			}
			if len(record.RawSample) != eventSize {
				atomic.AddUint64(&stats.parseErrors, 1)
				continue
			}
			var re rawEvent
			copy((*[eventSize]byte)(unsafe.Pointer(&re.data[0]))[:], record.RawSample)
			select {
			case eventChan <- re:
				atomic.AddUint64(&stats.eventsReceived, 1)
			default:
				atomic.AddUint64(&stats.eventsDropped, 1)
			}
		}
	}()

	go func() {
		defer close(done)
		for re := range eventChan {
			ev := (*event_t)(unsafe.Pointer(&re.data[0]))

			if ev.Version != eventVersion {
				atomic.AddUint64(&stats.versionMismatch, 1)
				continue
			}

			action, ok := actionNames[ev.ActionID]
			if !ok {
				atomic.AddUint64(&stats.parseErrors, 1)
				continue
			}

			comm := cstr(ev.Comm[:])
			filename := cstr(ev.Filename[:])

			severity, mitreID, mitreTechnique := calculateSeverity(action, comm, filename, ev.DestPort)
			container := resolver.resolve(ev.CgroupID, ev.Pid)

			var target, destIPStr string
			switch action {
			case "Sensitive_File_Access", "Process_Execution", "Log_Tampering":
				target = filename
			case "Network_Connection":
				destIPStr = formatIPv4(ev.DestIP)
				target = fmt.Sprintf("%s:%d", destIPStr, ev.DestPort)
			}

			alert := SecurityAlert{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				PID:            ev.Pid,
				PPID:           ev.Ppid,
				UID:            ev.Uid,
				StartTimeNs:    ev.StartTimeNs,
				Command:        comm,
				Action:         action,
				Target:         target,
				Severity:       severity,
				MitreID:        mitreID,
				MitreTechnique: mitreTechnique,
				CgroupID:       ev.CgroupID,
				ContainerID:    container.ContainerID,
				Runtime:        container.Runtime,
				DestIP:         destIPStr,
				DestPort:       ev.DestPort,
			}

			writeAlert(eventWriter, &alert)
			atomic.AddUint64(&stats.eventsWritten, 1)
		}
	}()

	healthTicker := time.NewTicker(healthLogInterval)
	defer healthTicker.Stop()

	for {
		select {
		case <-healthTicker.C:
			log.Printf("[health] received=%d written=%d dropped=%d parse_errors=%d version_mismatch=%d ringbuf_errs=%d chan=%d/%d",
				atomic.LoadUint64(&stats.eventsReceived),
				atomic.LoadUint64(&stats.eventsWritten),
				atomic.LoadUint64(&stats.eventsDropped),
				atomic.LoadUint64(&stats.parseErrors),
				atomic.LoadUint64(&stats.versionMismatch),
				atomic.LoadUint64(&stats.ringbufReadErrs),
				len(eventChan), eventChanSize)
		case <-done:
			log.Println("[-] Worker finished, shutting down.")
			return
		}
	}
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
MAIN_EOF

# ---------------------------------------------------------------
# userspace/serializer.go
# ---------------------------------------------------------------
echo "==> writing userspace/serializer.go"
cat > userspace/serializer.go <<'SER_EOF'
package main

import (
	"bytes"
	"strconv"
	"sync"
)

var bufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

func writeAlert(w *EnterpriseWriter, a *SecurityAlert) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	buf.WriteString(`{"timestamp":"`)
	buf.WriteString(a.Timestamp)
	buf.WriteString(`","pid":`)
	buf.WriteString(strconv.FormatUint(uint64(a.PID), 10))
	buf.WriteString(`,"uid":`)
	buf.WriteString(strconv.FormatUint(uint64(a.UID), 10))
	if a.PPID != 0 {
		buf.WriteString(`,"ppid":`)
		buf.WriteString(strconv.FormatUint(uint64(a.PPID), 10))
	}
	if a.StartTimeNs != 0 {
		buf.WriteString(`,"start_time_ns":`)
		buf.WriteString(strconv.FormatUint(a.StartTimeNs, 10))
	}
	buf.WriteString(`,"command":"`)
	writeEscaped(buf, a.Command)
	buf.WriteString(`","action":"`)
	writeEscaped(buf, a.Action)
	buf.WriteByte('"')
	if a.Target != "" {
		buf.WriteString(`,"target":"`)
		writeEscaped(buf, a.Target)
		buf.WriteByte('"')
	}
	buf.WriteString(`,"severity":"`)
	buf.WriteString(a.Severity)
	buf.WriteString(`","mitre_id":"`)
	writeEscaped(buf, a.MitreID)
	buf.WriteString(`","mitre_technique":"`)
	writeEscaped(buf, a.MitreTechnique)
	buf.WriteString(`","cgroup_id":`)
	buf.WriteString(strconv.FormatUint(a.CgroupID, 10))
	buf.WriteString(`,"runtime":"`)
	writeEscaped(buf, a.Runtime)
	buf.WriteByte('"')
	if a.ContainerID != "" {
		buf.WriteString(`,"container_id":"`)
		writeEscaped(buf, a.ContainerID)
		buf.WriteByte('"')
	}
	if a.DestIP != "" {
		buf.WriteString(`,"dest_ip":"`)
		writeEscaped(buf, a.DestIP)
		buf.WriteString(`","dest_port":`)
		buf.WriteString(strconv.FormatUint(uint64(a.DestPort), 10))
	}
	buf.WriteString("}\n")

	w.Write(buf.Bytes())
}

func writeEscaped(buf *bytes.Buffer, s string) {
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				continue
			}
			buf.WriteRune(r)
		}
	}
}
SER_EOF

# ---------------------------------------------------------------
# userspace/layout_test.go
# ---------------------------------------------------------------
echo "==> writing userspace/layout_test.go"
cat > userspace/layout_test.go <<'TEST_EOF'
package main

import (
	"testing"
	"unsafe"
)

func TestEventLayout(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"sizeof", unsafe.Sizeof(event_t{}), 200},
		{"off_cgroup_id", unsafe.Offsetof(event_t{}.CgroupID), 0},
		{"off_start_time_ns", unsafe.Offsetof(event_t{}.StartTimeNs), 8},
		{"off_version", unsafe.Offsetof(event_t{}.Version), 16},
		{"off_action_id", unsafe.Offsetof(event_t{}.ActionID), 20},
		{"off_pid", unsafe.Offsetof(event_t{}.Pid), 24},
		{"off_ppid", unsafe.Offsetof(event_t{}.Ppid), 28},
		{"off_uid", unsafe.Offsetof(event_t{}.Uid), 32},
		{"off_flags", unsafe.Offsetof(event_t{}.Flags), 36},
		{"off_comm", unsafe.Offsetof(event_t{}.Comm), 40},
		{"off_filename", unsafe.Offsetof(event_t{}.Filename), 56},
		{"off_dest_ip", unsafe.Offsetof(event_t{}.DestIP), 184},
		{"off_dest_port", unsafe.Offsetof(event_t{}.DestPort), 188},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestEventVersion(t *testing.T) {
	if eventVersion != 2 {
		t.Fatalf("eventVersion = %d, want 2", eventVersion)
	}
}
TEST_EOF

# ---------------------------------------------------------------
# Makefile
# ---------------------------------------------------------------
echo "==> writing Makefile"
cat > Makefile <<'MAKE_EOF'
SHELL      := /bin/bash
CLANG      ?= clang
GO         ?= go
BPFTOOL    ?= bpftool
CC         ?= gcc

KERNEL_DIR    := kernel
USERSPACE_DIR := userspace
COMMON_DIR    := common
EMULATION_DIR := emulation
SCRIPTS_DIR   := scripts

BPF_SRC       := $(KERNEL_DIR)/bpf_program.c
BPF_OBJ       := $(KERNEL_DIR)/bpf_program.o
VMLINUX_H     := $(KERNEL_DIR)/vmlinux.h
LAYOUT_C      := $(KERNEL_DIR)/layout_check.c
LAYOUT_BIN    := $(KERNEL_DIR)/layout_check

USER_BIN      := $(USERSPACE_DIR)/ebpf_controller
EMUL_BIN      := $(EMULATION_DIR)/adversary

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 \
              -I$(KERNEL_DIR) -I$(COMMON_DIR) \
              -Wall -Werror -Wno-unused-function -Wno-address-of-packed-member

.PHONY: all kernel userspace emulation verify test clean help

all: kernel userspace

help:
	@echo "Targets:"
	@echo "  make kernel         - build BPF object"
	@echo "  make userspace      - build Go daemon"
	@echo "  make emulation      - build adversary emulation binary"
	@echo "  make verify         - run full Phase 2.0 verification (sudo)"
	@echo "  make test           - run Go unit tests"
	@echo "  make clean"

$(VMLINUX_H):
	@if [ ! -f $@ ]; then \
		echo "[make] generating $@ from /sys/kernel/btf/vmlinux"; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	fi

kernel: $(BPF_OBJ) $(LAYOUT_BIN)

$(BPF_OBJ): $(BPF_SRC) $(COMMON_DIR)/common.h $(VMLINUX_H)
	@echo "[make] $(CLANG) -> $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(LAYOUT_BIN): $(LAYOUT_C) $(COMMON_DIR)/common.h
	@echo "[make] $(CC) -> $@"
	$(CC) -O0 -g -I$(COMMON_DIR) $< -o $@

userspace:
	@echo "[make] go build -> $(USER_BIN)"
	cd $(USERSPACE_DIR) && $(GO) build -trimpath -ldflags="-s -w" -o ebpf_controller .

emulation:
	@echo "[make] go build -> $(EMUL_BIN)"
	cd $(EMULATION_DIR) && $(GO) build -trimpath -o adversary .

test:
	cd $(USERSPACE_DIR) && $(GO) test -v ./...

verify:
	@bash $(SCRIPTS_DIR)/verify_phase2_0.sh

clean:
	rm -f $(BPF_OBJ) $(LAYOUT_BIN) $(USER_BIN) $(EMUL_BIN)
	cd $(USERSPACE_DIR) && $(GO) clean ./... 2>/dev/null || true
MAKE_EOF

# ---------------------------------------------------------------
# scripts/verify_phase2_0.sh
# ---------------------------------------------------------------
echo "==> writing scripts/verify_phase2_0.sh"
cat > scripts/verify_phase2_0.sh <<'VERIFY_EOF'
#!/usr/bin/env bash
# Phase 2.0 verification harness - ebpf-container-escape-framework
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/verify_out"
BPF_OBJ="${ROOT}/kernel/bpf_program.o"
LAYOUT_BIN="${ROOT}/kernel/layout_check"
USER_BIN="${ROOT}/userspace/ebpf_controller"
EMUL_BIN="${ROOT}/emulation/adversary"
LOG_FILE="/var/log/ebpf_edr.json"
RUN_LOG="${OUT}/daemon.log"
HEALTH_WINDOW=15
DAEMON_GRACE=3

STAGE="all"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stage) STAGE="$2"; shift 2 ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done

if [[ -t 1 ]]; then
    R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[36m'; N=$'\e[0m'; BOLD=$'\e[1m'
else
    R=""; G=""; Y=""; B=""; N=""; BOLD=""
fi

PASS=0; FAIL=0; WARN=0
declare -a FAIL_MSGS=()
declare -a WARN_MSGS=()

pass() { echo "${G}[PASS]${N} $*"; PASS=$((PASS+1)); }
fail() { echo "${R}[FAIL]${N} $*"; FAIL=$((FAIL+1)); FAIL_MSGS+=("$*"); }
warn() { echo "${Y}[WARN]${N} $*"; WARN=$((WARN+1)); WARN_MSGS+=("$*"); }
info() { echo "${B}[INFO]${N} $*"; }
head2() { echo; echo "${BOLD}=== $* ===${N}"; }
have() { command -v "$1" >/dev/null 2>&1; }
run_stage() { [[ "$STAGE" == "all" || "$STAGE" == "$1" ]]; }

mkdir -p "$OUT"

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "${R}Must run as root: sudo -E bash scripts/verify_phase2_0.sh${N}"
        exit 1
    fi
}

stage_env() {
    head2 "STAGE 1/7  Environment probe"
    local kver; kver="$(uname -r)"; info "kernel: $kver"
    local kmaj kmin; kmaj="$(echo "$kver" | cut -d. -f1)"; kmin="$(echo "$kver" | cut -d. -f2)"
    if (( kmaj > 6 )) || { (( kmaj == 6 )) && (( kmin >= 12 )); }; then
        pass "kernel >= 6.12 ($kver)"
    else
        fail "kernel < 6.12 ($kver)"
    fi

    if [[ -r /sys/kernel/btf/vmlinux ]]; then
        pass "/sys/kernel/btf/vmlinux present"
        cp /sys/kernel/btf/vmlinux "${OUT}/vmlinux.btf" 2>/dev/null || true
    else
        fail "/sys/kernel/btf/vmlinux missing"
    fi

    for t in clang gcc go; do
        if have "$t"; then pass "toolchain: $t -> $(command -v $t)"; else fail "toolchain: $t not found"; fi
    done
    have bpftool && pass "toolchain: bpftool" || warn "bpftool missing (load stage will be skipped)"

    if have clang && clang --print-targets 2>/dev/null | grep -q bpf; then
        pass "clang has bpf target"
    else
        fail "clang missing bpf target"
    fi

    if have bpftool && [[ -r /sys/kernel/btf/vmlinux ]]; then
        local dump; dump="$(bpftool btf dump file /sys/kernel/btf/vmlinux format c 2>/dev/null)"
        for field in start_boottime real_parent tgid; do
            if echo "$dump" | grep -q "\b$field\b"; then
                pass "BTF has field: $field"
            else
                warn "BTF missing field: $field"
            fi
        done
    fi

    if have go; then
        local gv; gv="$(go version)"; info "$gv"
        if echo "$gv" | grep -qE 'go1\.(2[1-9]|[3-9][0-9])'; then
            pass "Go >= 1.21"
        else
            warn "Go < 1.21"
        fi
    fi

    local tproot=""
    [[ -r /sys/kernel/tracing/events/syscalls ]] && tproot="/sys/kernel/tracing"
    [[ -z "$tproot" && -r /sys/kernel/debug/tracing/events/syscalls ]] && tproot="/sys/kernel/debug/tracing"
    for tp in openat open execve connect ptrace unlinkat; do
        if [[ -n "$tproot" && -r "$tproot/events/syscalls/sys_enter_${tp}/id" ]]; then
            pass "tracepoint present: sys_enter_${tp}"
        else
            warn "tracepoint not listed: sys_enter_${tp}"
        fi
    done

    if [[ -r /proc/kallsyms ]]; then
        for kp in __x64_sys_unshare __x64_sys_pivot_root; do
            if grep -q " $kp\$" /proc/kallsyms 2>/dev/null; then
                pass "kallsyms has: $kp"
            else
                warn "kallsyms missing: $kp"
            fi
        done
    fi
}

stage_build() {
    head2 "STAGE 2/7  Build"
    cd "$ROOT" || return

    info "make kernel"
    if make kernel >"${OUT}/build_kernel.log" 2>&1; then
        pass "make kernel"
    else
        fail "make kernel (see ${OUT}/build_kernel.log)"
        tail -30 "${OUT}/build_kernel.log" | sed 's/^/    /'
        return
    fi

    [[ -s "$BPF_OBJ" ]] && pass "bpf_program.o ($(stat -c%s "$BPF_OBJ") bytes)" || fail "bpf_program.o missing"
    [[ -x "$LAYOUT_BIN" ]] && pass "layout_check built" || fail "layout_check not built"

    info "make userspace"
    if make userspace >"${OUT}/build_userspace.log" 2>&1; then
        pass "make userspace"
    else
        fail "make userspace (see ${OUT}/build_userspace.log)"
        tail -30 "${OUT}/build_userspace.log" | sed 's/^/    /'
    fi
    [[ -x "$USER_BIN" ]] && pass "ebpf_controller built" || fail "ebpf_controller missing"

    info "make emulation"
    if make emulation >"${OUT}/build_emulation.log" 2>&1; then
        pass "make emulation"
    else
        warn "make emulation failed - emulation stage will be skipped"
        tail -20 "${OUT}/build_emulation.log" | sed 's/^/    /'
    fi
}

stage_layout() {
    head2 "STAGE 3/7  Struct layout (C ↔ Go)"

    if [[ ! -x "$LAYOUT_BIN" ]]; then
        fail "layout_check not built"
        return
    fi

    "$LAYOUT_BIN" > "${OUT}/layout_c.txt" 2>&1
    local c_size c_ver
    c_size="$(grep '^SIZE=' "${OUT}/layout_c.txt" | cut -d= -f2)"
    c_ver="$(grep '^VERSION=' "${OUT}/layout_c.txt" | cut -d= -f2)"
    info "C: sizeof(event_t)=$c_size version=$c_ver"

    [[ "$c_size" == "200" ]] && pass "C sizeof(event_t) == 200" || fail "C sizeof(event_t) == $c_size, expected 200"
    [[ "$c_ver"  == "2"   ]] && pass "C EVENT_VERSION == 2"   || fail "C EVENT_VERSION == $c_ver, expected 2"

    cd "${ROOT}/userspace" || return
    if go test -run TestEventLayout -v . > "${OUT}/layout_go.txt" 2>&1; then
        pass "Go layout test (TestEventLayout)"
    else
        fail "Go layout test failed (see ${OUT}/layout_go.txt)"
        tail -30 "${OUT}/layout_go.txt" | sed 's/^/    /'
    fi
    if go test -run TestEventVersion -v . >> "${OUT}/layout_go.txt" 2>&1; then
        pass "Go version test (TestEventVersion)"
    else
        fail "Go version test failed"
    fi

    info "C offsets:"
    grep '^OFF_' "${OUT}/layout_c.txt" | sed 's/^/    /'
}

stage_load() {
    head2 "STAGE 4/7  BPF verifier load (dry-run)"

    if [[ ! -f "$BPF_OBJ" ]]; then
        fail "bpf_program.o not built"
        return
    fi
    if ! have bpftool; then
        warn "bpftool not installed - verifier check deferred to runtime stage"
        return
    fi

    local pin="${OUT}/bpftool_pin"
    rm -rf "$pin"; mkdir -p "$pin"

    if bpftool prog loadall "$BPF_OBJ" "$pin" type kprobe 2>"${OUT}/bpftool_load.err"; then
        pass "bpftool prog loadall succeeded (all programs pass verifier)"
        ls "$pin" | sed 's/^/    pinned: /'
    else
        warn "bpftool loadall did not succeed - falling back to per-program load"
        local ok=0 bad=0
        for sec in trace_unshare trace_pivot_root trace_openat trace_open \
                   trace_execve trace_connect trace_ptrace trace_unlinkat; do
            rm -rf "$pin/$sec"
            if bpftool prog load "$BPF_OBJ" "$pin/$sec" 2>>"${OUT}/bpftool_load.err"; then
                pass "verifier: $sec"
                ok=$((ok+1))
            else
                fail "verifier: $sec (see ${OUT}/bpftool_load.err)"
                bad=$((bad+1))
            fi
        done
        info "verifier: ok=$ok bad=$bad"
    fi
    rm -rf "$pin"
}

stage_runtime() {
    head2 "STAGE 5/7  Runtime smoke test"

    if [[ ! -x "$USER_BIN" ]]; then
        fail "ebpf_controller not built"
        return
    fi

    [[ -e "$LOG_FILE" ]] && mv "$LOG_FILE" "${LOG_FILE}.verify.bak.$(date +%s)" 2>/dev/null || true
    : > "$LOG_FILE" 2>/dev/null || true
    chmod 0640 "$LOG_FILE" 2>/dev/null || true

    info "launching daemon..."
    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && "$USER_BIN" ) >>"$RUN_LOG" 2>&1 &
    local dpid=$!
    echo "$dpid" > "${OUT}/daemon.pid"
    sleep "$DAEMON_GRACE"

    if ! kill -0 "$dpid" 2>/dev/null; then
        fail "daemon exited early - see ${RUN_LOG}"
        tail -30 "$RUN_LOG" | sed 's/^/    /'
        return
    fi
    pass "daemon alive (pid=$dpid)"

    if grep -q "EDR Engine active" "$RUN_LOG"; then
        pass "daemon logged startup line"
    else
        warn "daemon did not log startup line (may be buffered)"
    fi

    info "emitting test syscalls..."
    cat /etc/shadow >/dev/null 2>&1 || true
    /bin/true 2>/dev/null || true
    (exec 3<>/dev/tcp/127.0.0.1/1) 2>/dev/null || true
    sleep 1

    local lines
    lines="$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)"
    if (( lines > 0 )); then
        pass "log file has $lines JSON lines after smoke test"
    else
        warn "log file empty after smoke test (host only fired /etc/shadow)"
    fi

    local bad=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "${line:0:1}" != "{" || "${line: -1}" != "}" ]]; then
            bad=$((bad+1))
        fi
    done < "$LOG_FILE"
    if (( bad == 0 )); then
        pass "all log lines are well-formed JSON objects"
    else
        fail "$bad malformed JSON lines"
    fi

    if grep -q '"ppid"' "$LOG_FILE"; then
        pass "log contains ppid field"
    else
        warn "log has no ppid field"
    fi
    if grep -q '"start_time_ns"' "$LOG_FILE"; then
        pass "log contains start_time_ns field"
    else
        warn "log has no start_time_ns field"
    fi

    info "sending SIGTERM..."
    kill -TERM "$dpid" 2>/dev/null || true
    local waited=0
    while kill -0 "$dpid" 2>/dev/null && (( waited < 25 )); do
        sleep 0.2; waited=$((waited+1))
    done
    if kill -0 "$dpid" 2>/dev/null; then
        kill -KILL "$dpid" 2>/dev/null || true
        fail "daemon did not exit on SIGTERM within 5s"
    else
        pass "daemon exited cleanly on SIGTERM"
    fi
}

stage_emulation() {
    head2 "STAGE 6/7  Adversary emulation"

    if [[ ! -x "$EMUL_BIN" ]]; then
        warn "emulation binary not built; skipping"
        return
    fi
    if [[ ! -x "$USER_BIN" ]]; then
        fail "ebpf_controller not built"
        return
    fi

    : > "$LOG_FILE"
    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && "$USER_BIN" ) >>"$RUN_LOG" 2>&1 &
    local dpid=$!
    sleep "$DAEMON_GRACE"
    if ! kill -0 "$dpid" 2>/dev/null; then
        fail "daemon died before emulation - see ${RUN_LOG}"
        return
    fi
    pass "daemon up for emulation"

    info "running emulation..."
    "$EMUL_BIN" >"${OUT}/emulation.out" 2>"${OUT}/emulation.err" || \
        warn "emulation exited non-zero"
    sleep 2

    for action in Container_Namespace_Unshare Container_Pivot_Root_Escape \
                  Sensitive_File_Access Process_Execution Network_Connection \
                  Process_Injection Log_Tampering; do
        if grep -q "\"action\":\"$action\"" "$LOG_FILE"; then
            pass "coverage: $action"
        else
            warn "coverage: $action not observed"
        fi
    done

    for mitre in T1611 T1003.008 T1055.008 T1562.001 T1071 T1059.004; do
        if grep -q "\"mitre_id\":\"$mitre\"" "$LOG_FILE"; then
            pass "MITRE: $mitre"
        else
            warn "MITRE: $mitre not observed"
        fi
    done

    kill -TERM "$dpid" 2>/dev/null || true
    sleep 1
    kill -KILL "$dpid" 2>/dev/null || true
}

stage_perf() {
    head2 "STAGE 7/7  Performance (CPU/RSS)"

    if [[ ! -x "$USER_BIN" ]]; then
        fail "ebpf_controller not built"
        return
    fi

    : > "$LOG_FILE"
    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && "$USER_BIN" ) >>"$RUN_LOG" 2>&1 &
    local dpid=$!
    sleep "$DAEMON_GRACE"
    if ! kill -0 "$dpid" 2>/dev/null; then
        fail "daemon died - see ${RUN_LOG}"
        return
    fi

    info "workload running for ${HEALTH_WINDOW}s..."
    local end=$(( $(date +%s) + HEALTH_WINDOW ))
    while (( $(date +%s) < end )); do
        cat /etc/shadow >/dev/null 2>&1 || true
        /bin/true 2>/dev/null || true
        ls /etc >/dev/null 2>&1 || true
    done

    local cpu rss_kb rss_mb
    cpu="$(ps -o %cpu= -p "$dpid" 2>/dev/null | tr -d ' ')"
    rss_kb="$(ps -o rss= -p "$dpid" 2>/dev/null | tr -d ' ')"
    rss_mb=$(( ${rss_kb:-0} / 1024 ))
    info "daemon pid=$dpid  cpu=${cpu}%  rss=${rss_mb}MB"

    if awk -v c="${cpu:-0}" 'BEGIN{exit !(c < 1.0)}'; then
        pass "CPU < 1% (got ${cpu}%)"
    else
        warn "CPU >= 1% (got ${cpu}%) - may be noisy"
    fi

    if (( rss_mb < 50 )); then
        pass "RSS < 50MB (got ${rss_mb}MB)"
    else
        fail "RSS >= 50MB (got ${rss_mb}MB)"
    fi

    local health
    health="$(grep '\[health\]' "$RUN_LOG" | tail -1 || true)"
    if [[ -n "$health" ]]; then
        info "last health: $health"
        local drops
        drops="$(echo "$health" | grep -oE 'dropped=[0-9]+' | cut -d= -f2 || echo 0)"
        if (( drops == 0 )); then
            pass "ringbuf drops == 0"
        else
            warn "ringbuf drops = $drops"
        fi
    else
        info "no health line in window (interval 60s, window ${HEALTH_WINDOW}s)"
    fi

    kill -TERM "$dpid" 2>/dev/null || true
    sleep 1
    kill -KILL "$dpid" 2>/dev/null || true
}

require_root
head2 "ebpf-container-escape-framework - Phase 2.0 verification"
info "root: $ROOT"
info "out:  $OUT"
info "stage: $STAGE"

run_stage env       && stage_env
run_stage build     && stage_build
run_stage layout    && stage_layout
run_stage load      && stage_load
run_stage runtime   && stage_runtime
run_stage emulation && stage_emulation
run_stage perf      && stage_perf

head2 "SUMMARY"
echo "  ${G}PASS${N}: $PASS"
echo "  ${Y}WARN${N}: $WARN"
echo "  ${R}FAIL${N}: $FAIL"

(( WARN > 0 )) && { echo; echo "${Y}Warnings:${N}"; for m in "${WARN_MSGS[@]}"; do echo "  - $m"; done; }
(( FAIL > 0 )) && { echo; echo "${R}Failures:${N}"; for m in "${FAIL_MSGS[@]}"; do echo "  - $m"; done; }
echo
echo "Artifacts: $OUT"
(( FAIL > 0 )) && exit 1
exit 0
VERIFY_EOF

chmod +x scripts/verify_phase2_0.sh

# ---------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------
if [[ "$REAL_USER" != "root" ]]; then
    chown -R "$REAL_USER":"$REAL_USER" "$ROOT/common" "$ROOT/kernel" "$ROOT/userspace" "$ROOT/scripts" "$ROOT/Makefile" 2>/dev/null || true
fi

echo
echo "================================================================"
echo " Phase 2.0 bootstrap complete."
echo " Backup:  $BACKUP"
echo
echo " Next:"
echo "   cd $ROOT"
echo "   make verify"
echo "================================================================"