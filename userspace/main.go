package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	eventChanSize     = 4096
	eventSize         = 208
	eventWords        = eventSize / 8
	eventVersion      = 3
	defaultHealthTick = 60 * time.Second
	ActionMaxID       = 17
)

/* Action IDs - must match enum event_action in common.h */
const (
	ActionUnknown                   = 0
	ActionContainerNamespaceUnshare = 1
	ActionContainerPivotRootEscape  = 2
	ActionSensitiveFileAccess       = 3
	ActionProcessExecution          = 4
	ActionNetworkConnection         = 5
	ActionProcessInjection          = 6
	ActionLogTampering              = 7
	ActionEbpfTampering             = 8
	ActionPerfEventOpen             = 9
	ActionSuspiciousMount           = 10
	ActionNamespaceSwitch           = 11
	ActionChrootEscape              = 12
	ActionExecutableMemory          = 13
	ActionCorePatternModification   = 14
	ActionCgroupReleaseAgent        = 15
	ActionCanaryTriggered           = 16
)

var actionNames = map[uint32]string{
	ActionContainerNamespaceUnshare: "Container_Namespace_Unshare",
	ActionContainerPivotRootEscape:  "Container_Pivot_Root_Escape",
	ActionSensitiveFileAccess:       "Sensitive_File_Access",
	ActionProcessExecution:          "Process_Execution",
	ActionNetworkConnection:         "Network_Connection",
	ActionProcessInjection:          "Process_Injection",
	ActionLogTampering:              "Log_Tampering",
	ActionEbpfTampering:             "Ebpf_Tampering",
	ActionPerfEventOpen:             "Perf_Event_Open",
	ActionSuspiciousMount:           "Suspicious_Mount",
	ActionNamespaceSwitch:           "Namespace_Switch",
	ActionChrootEscape:              "Chroot_Escape",
	ActionExecutableMemory:          "Executable_Memory",
	ActionCorePatternModification:   "Core_Pattern_Modification",
	ActionCgroupReleaseAgent:        "Cgroup_Release_Agent",
	ActionCanaryTriggered:           "Canary_Triggered",
}

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
	AuxU16      uint16
	AuxU64      uint64
	AuxU32      uint32
}

type SecurityAlert struct {
	Timestamp         string         `json:"timestamp"`
	PID               uint32         `json:"pid"`
	PPID              uint32         `json:"ppid"`
	UID               uint32         `json:"uid"`
	StartTimeNs       uint64         `json:"start_time_ns"`
	Command           string         `json:"command"`
	Action            string         `json:"action"`
	Target            string         `json:"target,omitempty"`
	Severity          string         `json:"severity"`
	MitreID           string         `json:"mitre_id"`
	MitreTechnique    string         `json:"mitre_technique"`
	CgroupID          uint64         `json:"cgroup_id"`
	ContainerID       string         `json:"container_id,omitempty"`
	Runtime           string         `json:"runtime"` // Only one declaration of Runtime
	K8sPodName        string         `json:"k8s_pod_name,omitempty"`
	K8sNamespace      string         `json:"k8s_namespace,omitempty"`
	K8sServiceAccount string         `json:"k8s_service_account,omitempty"`
	DestIP            string         `json:"dest_ip,omitempty"`
	DestPort          uint16         `json:"dest_port,omitempty"`
	CgroupPath        string         `json:"cgroup_path,omitempty"`
	LineageSummary    string         `json:"lineage_summary,omitempty"`
	Lineage           []lineageEntry `json:"lineage,omitempty"`
	LineageTruncated  bool           `json:"lineage_truncated,omitempty"`
	AuxU16            uint16         `json:"aux_u16,omitempty"`
	AuxU32            uint32         `json:"aux_u32,omitempty"`
	AuxU64            uint64         `json:"aux_u64,omitempty"`
}

var suspiciousPorts = map[uint16]bool{4444: true, 1337: true, 31337: true, 6666: true, 6697: true}

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
	case "Ebpf_Tampering":
		return "HIGH", "T1562.001", "Impair Defenses: eBPF Tampering"
	case "Perf_Event_Open":
		return "MEDIUM", "T1562.001", "Impair Defenses: perf_event_open"
	case "Suspicious_Mount":
		return "HIGH", "T1611", "Escape to Host: mount"
	case "Namespace_Switch":
		return "HIGH", "T1611", "Escape to Host: setns"
	case "Chroot_Escape":
		return "HIGH", "T1611", "Escape to Host: chroot"
	case "Executable_Memory":
		return "MEDIUM", "T1620", "Reflective Code Loading"
	case "Core_Pattern_Modification":
		return "CRITICAL", "T1611", "Escape to Host: core_pattern"
	case "Cgroup_Release_Agent":
		return "CRITICAL", "T1611", "Escape to Host: cgroup release_agent"
	case "Canary_Triggered":
		return "CRITICAL", "T1552.001", "Unsecured Credentials: Canary File Accessed"
	default:
		return "INFO", "T1204", "User Execution"
	}
}

type agentStats struct {
	eventsReceived  uint64
	eventsDropped   uint64
	eventsWritten   uint64
	eventsRateLim   uint64
	parseErrors     uint64
	versionMismatch uint64
	ringbufReadErrs uint64
	reloads         uint64
	reloadFails     uint64
}

var stats agentStats

type rawEvent struct{ data [eventWords]uint64 }

var (
	cfgMu sync.RWMutex
	cfg   Config
)

func getConfig() Config  { cfgMu.RLock(); defer cfgMu.RUnlock(); return cfg }
func setConfig(c Config) { cfgMu.Lock(); cfg = c; cfgMu.Unlock() }

func main() {
	var (
		flagConfig   = flag.String("config", "/etc/ebpf-edr/config.toml", "path to config.toml")
		flagLogPath  = flag.String("log-path", "", "override log.path")
		flagLogLevel = flag.String("log-level", "", "override log.level")
		flagMode     = flag.String("mode", "", "override mode (audit only)")
		flagBPFObj   = flag.String("bpf-obj", "../kernel/bpf_program.o", "path to BPF object file")
		flagHealth   = flag.Duration("health-interval", defaultHealthTick, "health log interval")
	)
	flag.Parse()

	// Register signal handlers BEFORE any BPF load so that SIGHUP / SIGTERM
	// sent during the (slow) verifier pass are captured rather than killing
	// the process with default disposition. Channels are buffered (cap 1)
	// so a signal delivered before the consumer goroutine starts is held.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	reloadChan := make(chan os.Signal, 1)
	signal.Notify(reloadChan, syscall.SIGHUP)

	cfgPath := *flagConfig
	if v := os.Getenv("EDR_CONFIG"); v != "" {
		cfgPath = v
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	loaded.ApplyEnvAndFlags(*flagLogPath, *flagLogLevel, *flagMode)
	if err := loaded.Validate(); err != nil {
		log.Fatalf("config invalid: %v", err)
	}
	setConfig(loaded)

	log.Printf("[-] config loaded: path=%q mode=%q level=%q log=%q rate=%d/%d",
		cfgPath, loaded.Mode, loaded.Log.Level, loaded.Log.Path,
		loaded.Rates.EventsPerSec, loaded.Rates.Burst)

	// Self-exclusion is PID-based: main() publishes its tgid into the
	// self_tgid BPF map after load. The former comm-based auto-allowlist
	// ("ebpf-edr"/"ebpf_controller") was spoofable via prctl(PR_SET_NAME)
	// and is deliberately not used anymore; comm_allowlist remains a
	// user-configured filter only.

	var (
		rotLogger io.Closer
	)
	defer func() {
		if rotLogger != nil {
			rotLogger.Close()
		}
	}()

	resolver := newContainerResolver()
	lineageC := newLineageCache(loaded.Context.LineageCacheSize)
	cgroupC := newCgroupPathCache(loaded.Context.CgroupCacheSize)
	k8sResolver := newK8sResolver()
	defer k8sResolver.Close()

	// ---- Output sink (Phase 2.6) ----
	enc, err := newEncoder(loaded.Output.Format)
	if err != nil {
		log.Fatalf("output encoder: %v", err)
	}

	var sink Sink
	switch loaded.Output.Target {
	case "", "file":
		logPath := loaded.Output.Path
		if logPath == "" {
			logPath = loaded.Log.Path
		}
		ew, rl := NewEnterpriseWriter(logPath, loaded.Log.MaxBytes, loaded.Log.MaxBackups)
		rotLogger = rl
		sink = newFileSink(enc, ew)
	case "stdout":
		sink = newFileSink(enc, os.Stdout)
	case "syslog":
		scfg := loaded.Output.Syslog
		tr, err := newSyslogTransport(scfg.Network, scfg.Address, scfg.Tag, scfg.TLSCA)
		if err != nil {
			log.Fatalf("syslog transport: %v", err)
		}
		nsCfg := defaultNetworkSinkConfig()
		sink = newNetworkSink(enc, tr, nsCfg)
	case "webhook":
		wcfg := loaded.Output.Webhook
		timeout := parseDurationOr(wcfg.Timeout, 5*time.Second)
		tr, err := newWebhookTransport(wcfg.URL, wcfg.AuthHeader, enc.ContentType(),
			wcfg.BatchStyle, wcfg.SplunkHEC, wcfg.InsecureSkipVerify, timeout)
		if err != nil {
			log.Fatalf("webhook transport: %v", err)
		}
		nsCfg := defaultNetworkSinkConfig()
		if wcfg.BatchSize > 0 {
			nsCfg.BatchSize = wcfg.BatchSize
		}
		if wcfg.FlushInterval != "" {
			nsCfg.FlushInterval = parseDurationOr(wcfg.FlushInterval, nsCfg.FlushInterval)
		}
		sink = newNetworkSink(enc, tr, nsCfg)
	default:
		log.Fatalf("unknown output target %q", loaded.Output.Target)
	}
	defer sink.Close()

	log.Printf("[-] output sink: %s", sink.Describe())

	spec, err := ebpf.LoadCollectionSpec(*flagBPFObj)
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}

	var objs struct {
		ProgUnshare   *ebpf.Program `ebpf:"trace_unshare"`
		ProgPivotRoot *ebpf.Program `ebpf:"trace_pivot_root"`
		ProgOpenat    *ebpf.Program `ebpf:"trace_openat"`
		ProgOpen      *ebpf.Program `ebpf:"trace_open"`
		ProgOpenat2   *ebpf.Program `ebpf:"trace_openat2"`
		ProgExecve    *ebpf.Program `ebpf:"trace_execve"`
		ProgConnect   *ebpf.Program `ebpf:"trace_connect"`
		ProgPtrace    *ebpf.Program `ebpf:"trace_ptrace"`
		ProgUnlinkat  *ebpf.Program `ebpf:"trace_unlinkat"`
		ProgBPF       *ebpf.Program `ebpf:"trace_bpf"`
		ProgPerf      *ebpf.Program `ebpf:"trace_perf_event_open"`
		ProgMount     *ebpf.Program `ebpf:"trace_mount"`
		ProgSetns     *ebpf.Program `ebpf:"trace_setns"`
		ProgChroot    *ebpf.Program `ebpf:"trace_chroot"`
		ProgMprotect  *ebpf.Program `ebpf:"trace_mprotect"`
		Events        *ebpf.Map     `ebpf:"events"`
		CommAllow     *ebpf.Map     `ebpf:"comm_allowlist"`
		CgAllow       *ebpf.Map     `ebpf:"cgroup_allowlist"`
		ActionEnabled *ebpf.Map     `ebpf:"action_enabled"`
		CanaryPaths   *ebpf.Map     `ebpf:"canary_paths"`
		SelfTgid      *ebpf.Map     `ebpf:"self_tgid"`
	}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("load objects: %v", err)
	}
	defer objs.ProgUnshare.Close()
	defer objs.ProgPivotRoot.Close()
	defer objs.ProgOpenat.Close()
	defer objs.ProgOpen.Close()
	defer objs.ProgOpenat2.Close()
	defer objs.ProgExecve.Close()
	defer objs.ProgConnect.Close()
	defer objs.ProgPtrace.Close()
	defer objs.ProgUnlinkat.Close()
	defer objs.ProgBPF.Close()
	defer objs.ProgPerf.Close()
	defer objs.ProgMount.Close()
	defer objs.ProgSetns.Close()
	defer objs.ProgChroot.Close()
	defer objs.ProgMprotect.Close()
	defer objs.Events.Close()
	defer objs.CommAllow.Close()
	defer objs.CgAllow.Close()
	defer objs.ActionEnabled.Close()
	defer objs.CanaryPaths.Close()
	defer objs.SelfTgid.Close()

	if err := populateFilterMaps(objs.CommAllow, objs.CgAllow, loaded); err != nil {
		log.Fatalf("populate filter maps: %v", err)
	}
	if err := populateCanaryMap(objs.CanaryPaths, loaded); err != nil {
		log.Fatalf("populate canary map: %v", err)
	}
	if err := populateActionEnabled(objs.ActionEnabled, loaded); err != nil {
		log.Fatalf("populate action_enabled: %v", err)
	}
	// Publish our tgid so kernel-side self-exclusion works. os.Getpid()
	// equals the tgid the kernel sees for this process.
	if err := objs.SelfTgid.Put(uint32(0), uint32(os.Getpid())); err != nil {
		log.Fatalf("publish self tgid: %v", err)
	}
	log.Printf("[-] filter maps: comm=%d cgroup=%d disabled_actions=%d",
		len(loaded.Filter.CommAllowlist), len(loaded.Filter.CgroupAllowlist),
		len(loaded.DisabledActions))

	attach := func(name string, fn func() error) {
		if err := fn(); err != nil {
			log.Fatalf("attach %s: %v", name, err)
		}
	}
	var (
		kpUnshare, kpPivot              link.Link
		tpOpenat, tpOpen, tpOpenat2     link.Link
		tpExecve, tpConn                link.Link
		tpPtrace, tpUnlinkat            link.Link
		tpBPF, tpPerf, tpMount, tpSetns link.Link
		tpChroot, tpMprotect            link.Link
	)
	attach("unshare", func() (e error) { kpUnshare, e = link.Kprobe("__x64_sys_unshare", objs.ProgUnshare, nil); return })
	attach("pivot_root", func() (e error) { kpPivot, e = link.Kprobe("__x64_sys_pivot_root", objs.ProgPivotRoot, nil); return })
	attach("openat", func() (e error) {
		tpOpenat, e = link.Tracepoint("syscalls", "sys_enter_openat", objs.ProgOpenat, nil)
		return
	})
	attach("open", func() (e error) {
		tpOpen, e = link.Tracepoint("syscalls", "sys_enter_open", objs.ProgOpen, nil)
		return
	})
	attach("openat2", func() (e error) {
		tpOpenat2, e = link.Tracepoint("syscalls", "sys_enter_openat2", objs.ProgOpenat2, nil)
		return
	})
	attach("execve", func() (e error) {
		tpExecve, e = link.Tracepoint("syscalls", "sys_enter_execve", objs.ProgExecve, nil)
		return
	})
	attach("connect", func() (e error) {
		tpConn, e = link.Tracepoint("syscalls", "sys_enter_connect", objs.ProgConnect, nil)
		return
	})
	attach("ptrace", func() (e error) {
		tpPtrace, e = link.Tracepoint("syscalls", "sys_enter_ptrace", objs.ProgPtrace, nil)
		return
	})
	attach("unlinkat", func() (e error) {
		tpUnlinkat, e = link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.ProgUnlinkat, nil)
		return
	})
	attach("bpf", func() (e error) { tpBPF, e = link.Tracepoint("syscalls", "sys_enter_bpf", objs.ProgBPF, nil); return })
	attach("perf_event_open", func() (e error) {
		tpPerf, e = link.Tracepoint("syscalls", "sys_enter_perf_event_open", objs.ProgPerf, nil)
		return
	})
	attach("mount", func() (e error) {
		tpMount, e = link.Tracepoint("syscalls", "sys_enter_mount", objs.ProgMount, nil)
		return
	})
	attach("setns", func() (e error) {
		tpSetns, e = link.Tracepoint("syscalls", "sys_enter_setns", objs.ProgSetns, nil)
		return
	})
	attach("chroot", func() (e error) {
		tpChroot, e = link.Tracepoint("syscalls", "sys_enter_chroot", objs.ProgChroot, nil)
		return
	})
	attach("mprotect", func() (e error) {
		tpMprotect, e = link.Tracepoint("syscalls", "sys_enter_mprotect", objs.ProgMprotect, nil)
		return
	})
	defer kpUnshare.Close()
	defer kpPivot.Close()
	defer tpOpenat.Close()
	defer tpOpen.Close()
	defer tpOpenat2.Close()
	defer tpExecve.Close()
	defer tpConn.Close()
	defer tpPtrace.Close()
	defer tpUnlinkat.Close()
	defer tpBPF.Close()
	defer tpPerf.Close()
	defer tpMount.Close()
	defer tpSetns.Close()
	defer tpChroot.Close()
	defer tpMprotect.Close()

	log.Printf("[-] EDR Engine active (event version %d, mode=%s). Streaming to stdout + %s",
		eventVersion, loaded.Mode, loaded.Log.Path)

	// Readiness + liveness surface: touch a heartbeat file immediately
	// (Kubernetes exec probes test its freshness) and tell systemd we are
	// ready (Type=notify; no-op without NOTIFY_SOCKET).
	heartbeatPath := os.Getenv("EDR_HEARTBEAT_PATH")
	if heartbeatPath == "" {
		heartbeatPath = "/var/run/ebpf-edr/heartbeat"
	}
	if err := touchHeartbeat(heartbeatPath); err != nil {
		log.Printf("[-] heartbeat file unavailable (%v); probes/watchdogs relying on it will not see updates", err)
	}
	sdNotify("READY=1")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	// shutdown is closed once the ringbuf reader has been closed by a
	// signal, so background loops can stop sleeping immediately.
	shutdown := make(chan struct{})
	go func() {
		<-sigChan
		rd.Close()
		close(shutdown)
	}()

	rl := newRateLimiter(loaded.Rates.EventsPerSec, loaded.Rates.Burst)

	go func() {
		for range reloadChan {
			newCfg, err := LoadConfig(cfgPath)
			if err != nil {
				atomic.AddUint64(&stats.reloadFails, 1)
				log.Printf("[reload] parse failed: %v (keeping current)", err)
				continue
			}
			newCfg.ApplyEnvAndFlags(*flagLogPath, *flagLogLevel, *flagMode)
			if err := newCfg.Validate(); err != nil {
				atomic.AddUint64(&stats.reloadFails, 1)
				log.Printf("[reload] invalid: %v (keeping current)", err)
				continue
			}
			if err := populateFilterMaps(objs.CommAllow, objs.CgAllow, newCfg); err != nil {
				atomic.AddUint64(&stats.reloadFails, 1)
				log.Printf("[reload] filter map update failed: %v", err)
				continue
			}
			if err := populateActionEnabled(objs.ActionEnabled, newCfg); err != nil {
				atomic.AddUint64(&stats.reloadFails, 1)
				log.Printf("[reload] action_enabled update failed: %v", err)
				continue
			}
			rl.setRates(newCfg.Rates.EventsPerSec, newCfg.Rates.Burst)
			setConfig(newCfg)
			atomic.AddUint64(&stats.reloads, 1)
			log.Printf("[reload] applied: level=%q rate=%d/%d disabled=%d",
				newCfg.Log.Level, newCfg.Rates.EventsPerSec, newCfg.Rates.Burst,
				len(newCfg.DisabledActions))
		}
	}()

	eventChan := make(chan rawEvent, eventChanSize)
	done := make(chan struct{})

	go func() {
		defer close(eventChan)
		// A transient ringbuf read error used to terminate the producer
		// and take the whole sensor down; only a closed reader ends the
		// loop now, anything else is retried with capped backoff.
		const retryBase = 50 * time.Millisecond
		const retryMax = 5 * time.Second
		backoff := retryBase
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, os.ErrClosed) {
					return
				}
				atomic.AddUint64(&stats.ringbufReadErrs, 1)
				log.Printf("[ringbuf] read error: %v (retrying in %v)", err, backoff)
				select {
				case <-shutdown:
					return
				case <-time.After(backoff):
				}
				if backoff < retryMax {
					backoff *= 2
				}
				continue
			}
			backoff = retryBase
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
			if !rl.allow(ev.ActionID) {
				atomic.AddUint64(&stats.eventsRateLim, 1)
				continue
			}

			comm := cstr(ev.Comm[:])
			filename := cstr(ev.Filename[:])
			severity, mitreID, mitreTechnique := calculateSeverity(action, comm, filename, ev.DestPort)
			container := resolver.resolve(ev.CgroupID, ev.Pid)
			k8sInfo, _ := k8sResolver.Lookup(container.ContainerID)

			var lineageBuf [16]lineageEntry
			lineage, lineageComplete := lineageC.buildLineage(
				lineageBuf[:0], ev.Pid, ev.Ppid, ev.StartTimeNs, comm,
				loaded.Context.LineageMaxDepth)
			lineageTruncated := !lineageComplete
			lineageSummary := buildLineageSummary(lineage)

			var cgroupPath string
			if ev.CgroupID != 0 {
				if p, ok := cgroupC.get(ev.CgroupID); ok {
					cgroupPath = p
				} else if p, ok := readCgroupPath(ev.Pid); ok {
					cgroupC.put(ev.CgroupID, p)
					cgroupPath = p
				}
			}

			var target, destIPStr string
			switch action {
			case "Sensitive_File_Access", "Process_Execution", "Log_Tampering",
				"Suspicious_Mount", "Chroot_Escape",
				"Core_Pattern_Modification", "Cgroup_Release_Agent":
				target = filename
			case "Network_Connection":
				destIPStr = formatIPv4(ev.DestIP)
				target = fmt.Sprintf("%s:%d", destIPStr, ev.DestPort)
			}

			alert := SecurityAlert{
				Timestamp:         time.Now().UTC().Format(time.RFC3339),
				PID:               ev.Pid,
				PPID:              ev.Ppid,
				UID:               ev.Uid,
				StartTimeNs:       ev.StartTimeNs,
				Command:           comm,
				Action:            action,
				Target:            target,
				Severity:          severity,
				MitreID:           mitreID,
				MitreTechnique:    mitreTechnique,
				CgroupID:          ev.CgroupID,
				ContainerID:       container.ContainerID,
				Runtime:           container.Runtime,
				CgroupPath:        cgroupPath,
				LineageSummary:    lineageSummary,
				Lineage:           lineage,
				LineageTruncated:  lineageTruncated,
				DestIP:            destIPStr,
				DestPort:          ev.DestPort,
				AuxU16:            ev.AuxU16,
				AuxU32:            ev.AuxU32,
				AuxU64:            ev.AuxU64,
				K8sPodName:        k8sInfo.PodName,
				K8sNamespace:      k8sInfo.Namespace,
				K8sServiceAccount: k8sInfo.ServiceAccount,
			}

			sink.Submit(&alert)
			atomic.AddUint64(&stats.eventsWritten, 1)
		}
	}()

	healthTicker := time.NewTicker(*flagHealth)
	defer healthTicker.Stop()

	// Beat faster than systemd's WatchdogSec (30s) and generously inside
	// any liveness threshold built on the heartbeat file.
	beatTicker := time.NewTicker(10 * time.Second)
	defer beatTicker.Stop()

	for {
		select {
		case <-beatTicker.C:
			_ = touchHeartbeat(heartbeatPath)
			sdNotify("WATCHDOG=1")
		case <-healthTicker.C:
			lcHits, lcMisses := lineageC.stats()
			st := sink.Stats()
			log.Printf("[health] recv=%d written=%d dropped=%d rate_limited=%d parse_err=%d ver_mismatch=%d ringbuf_err=%d reloads=%d reload_fail=%d chan=%d/%d lineage_cache=%d/%d lineage_hits=%d lineage_misses=%d cgroup_cache=%d/%d sink_sent=%d sink_failed=%d sink_dropped=%d sink_retries=%d sink_queue=%d sink_circuit=%v",
				atomic.LoadUint64(&stats.eventsReceived),
				atomic.LoadUint64(&stats.eventsWritten),
				atomic.LoadUint64(&stats.eventsDropped),
				atomic.LoadUint64(&stats.eventsRateLim),
				atomic.LoadUint64(&stats.parseErrors),
				atomic.LoadUint64(&stats.versionMismatch),
				atomic.LoadUint64(&stats.ringbufReadErrs),
				atomic.LoadUint64(&stats.reloads),
				atomic.LoadUint64(&stats.reloadFails),
				len(eventChan), eventChanSize,
				lineageC.size(), lineageC.capacity(),
				lcHits, lcMisses,
				cgroupC.size(), cgroupC.capacity(),
				st.Sent, st.Failed, st.Dropped, st.Retries, st.QueueDepth, st.CircuitOpen)
		case <-done:
			log.Println("[-] Worker finished, shutting down.")
			if err := sink.Flush(3 * time.Second); err != nil {
				log.Printf("[shutdown] sink flush incomplete: %v", err)
			}
			return
		}
	}
}

func populateActionEnabled(m *ebpf.Map, c Config) error {
	disabled := map[string]bool{}
	for _, name := range c.DisabledActions {
		disabled[name] = true
	}
	for id := uint32(0); id < 32; id++ {
		var enabled uint32
		if id >= 1 && id < ActionMaxID {
			if name, ok := actionNames[id]; ok && !disabled[name] {
				enabled = 1
			}
		}
		if err := m.Put(id, enabled); err != nil {
			return fmt.Errorf("put action_enabled[%d]: %w", id, err)
		}
	}
	return nil
}

func populateFilterMaps(commMap, cgMap *ebpf.Map, c Config) error {
	if err := clearMap(commMap); err != nil {
		return fmt.Errorf("clear comm: %w", err)
	}
	if err := clearMap(cgMap); err != nil {
		return fmt.Errorf("clear cgroup: %w", err)
	}
	var one uint32 = 1
	for _, name := range c.Filter.CommAllowlist {
		var key [16]byte
		copy(key[:], name)
		if err := commMap.Put(key, one); err != nil {
			return fmt.Errorf("put comm %q: %w", name, err)
		}
	}
	for _, cg := range c.Filter.CgroupAllowlist {
		k := cg
		if err := cgMap.Put(k, one); err != nil {
			return fmt.Errorf("put cgroup %d: %w", cg, err)
		}
	}
	return nil
}

func populateCanaryMap(m *ebpf.Map, c Config) error {
	var one uint32 = 1
	for _, p := range c.Filter.CanaryPaths {
		var key [128]byte
		copy(key[:], p)
		if err := m.Put(key, one); err != nil {
			return fmt.Errorf("put canary %q: %w", p, err)
		}
	}
	return nil
}

func clearMap(m *ebpf.Map) error {
	iter := m.Iterate()
	var key, value []byte
	var toDelete [][]byte
	for iter.Next(&key, &value) {
		kc := make([]byte, len(key))
		copy(kc, key)
		toDelete = append(toDelete, kc)
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range toDelete {
		if err := m.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func parseDurationOr(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
