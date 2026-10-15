package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	logPath       = "/var/log/ebpf_edr.json"
	logMaxBytes   = 50 * 1024 * 1024
	logMaxBackups = 5

	eventChanSize = 4096

	healthLogInterval = 60 * time.Second
)

type event_t struct {
	CgroupID  uint64
	Pid       uint32
	Ppid      uint32
	Uid       uint32
	Comm      [16]byte
	Action    [32]byte
	Filename  [64]byte
	Reserved  [4]byte
	DestIP    [4]byte
	DestPort  uint16
	Reserved2 [2]byte
}

type SecurityAlert struct {
    Timestamp   string `json:"timestamp"`
    PID         uint32 `json:"pid"`
    UID         uint32 `json:"uid"`
    Command     string `json:"command"`
    Action      string `json:"action"`
    Target      string `json:"target,omitempty"`
    Severity    string `json:"severity"`
    MitreID     string `json:"mitre_id"`
    MitreTechnique string `json:"mitre_technique"`
    CgroupID    uint64 `json:"cgroup_id"`
    ContainerID string `json:"container_id,omitempty"`
    Runtime     string `json:"runtime"`
    DestIP      string `json:"dest_ip,omitempty"`
    DestPort    uint16 `json:"dest_port,omitempty"`
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
	eventsReceived uint64
	eventsDropped  uint64
	eventsWritten  uint64
	parseErrors    uint64
}

var stats agentStats

type rawEvent struct {
	data []byte
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

	log.Printf("[-] EDR Engine active. Streaming structured JSON security events to stdout + %s", logPath)

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
				log.Printf("Reading ringbuf finished or error: %v", err)
				return
			}
			atomic.AddUint64(&stats.eventsReceived, 1)

			buf := make([]byte, len(record.RawSample))
			copy(buf, record.RawSample)

			select {
			case eventChan <- rawEvent{data: buf}:
			default:

				atomic.AddUint64(&stats.eventsDropped, 1)
			}
		}
	}()

	go func() {
		defer close(done)
		var event event_t
		for re := range eventChan {
			if err := binary.Read(bytes.NewReader(re.data), binary.LittleEndian, &event); err != nil {
				atomic.AddUint64(&stats.parseErrors, 1)
				continue
			}

			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
			action := string(bytes.TrimRight(event.Action[:], "\x00"))
			filename := string(bytes.TrimRight(event.Filename[:], "\x00"))

			severity, mitreID, mitreTechnique := calculateSeverity(action, comm, filename, event.DestPort)
			container := resolver.resolve(event.CgroupID, event.Pid)

			var target string
			var destIPStr string

			switch action {
			case "Sensitive_File_Access", "Process_Execution", "Log_Tampering":
				target = filename
			case "Network_Connection":
				destIPStr = formatIPv4(event.DestIP)
				target = fmt.Sprintf("%s:%d", destIPStr, event.DestPort)
			default:
				target = "" 
			}

			alert := SecurityAlert{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
    			PID:            event.Pid,
    			UID:            event.Uid,
    			Command:        comm,
    			Action:         action,
    			Target:         target,
    			Severity:       severity,
    			MitreID:        mitreID,
    			MitreTechnique: mitreTechnique,
    			CgroupID:       event.CgroupID,
    			ContainerID:    container.ContainerID,
    			Runtime:        container.Runtime,
    			DestIP:         destIPStr,
    			DestPort:       event.DestPort,
		}

			eventWriter.Write(serializeAlert(&alert))
			atomic.AddUint64(&stats.eventsWritten, 1)
		}
	}()

	healthTicker := time.NewTicker(healthLogInterval)
	defer healthTicker.Stop()

	for {
		select {
		case <-healthTicker.C:
			log.Printf("[health] received=%d written=%d dropped=%d parse_errors=%d chan_len=%d/%d",
				atomic.LoadUint64(&stats.eventsReceived),
				atomic.LoadUint64(&stats.eventsWritten),
				atomic.LoadUint64(&stats.eventsDropped),
				atomic.LoadUint64(&stats.parseErrors),
				len(eventChan), eventChanSize)
		case <-done:
			log.Println("[-] Worker finished, shutting down.")
			return
		}
	}
}
