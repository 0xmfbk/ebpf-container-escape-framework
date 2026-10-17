package main

import (
	"encoding/json"
	"strconv"
	"strings"
)

type ecsEncoder struct{}

func (ecsEncoder) Name() string        { return "ecs" }
func (ecsEncoder) ContentType() string { return "application/json" }

func (ecsEncoder) Encode(a *SecurityAlert) ([]byte, error) {
	process := map[string]any{
		"pid":    a.PID,
		"parent": map[string]any{"pid": a.PPID},
		"name":   a.Command,
	}
	doc := map[string]any{
		"@timestamp": a.Timestamp,
		"event": map[string]any{
			"kind":     "alert",
			"category": []string{ecsCategory(a.Action)},
			"type":     []string{ecsType(a.Action)},
			"action":   a.Action,
			"severity": ecsSeverity(a.Severity),
			"module":   "ebpf-edr",
			"dataset":  "ebpf_edr.events",
		},
		"process": process,
		"user":    map[string]any{"id": strconv.FormatUint(uint64(a.UID), 10)},
		"host":    map[string]any{"os": map[string]any{"family": "linux", "type": "linux"}},
		"rule":    map[string]any{"id": a.MitreID, "name": a.MitreTechnique},
		"threat": map[string]any{
			"framework": "MITRE ATT&CK",
			"technique": map[string]any{
				"id":        a.MitreID,
				"name":      a.MitreTechnique,
				"reference": "https://attack.mitre.org/techniques/" + ecsMitreURL(a.MitreID) + "/",
			},
		},
		"message": a.Action + " " + a.Target,
	}
	if a.ContainerID != "" {
		doc["container"] = map[string]any{"id": a.ContainerID, "runtime": a.Runtime}
	}
	if a.DestIP != "" {
		doc["destination"] = map[string]any{"ip": a.DestIP, "port": a.DestPort}
	}
	if a.CgroupPath != "" {
		doc["host"].(map[string]any)["containerized"] = true
	}
	if a.LineageSummary != "" {
		doc["ebpf_edr"] = map[string]any{"lineage_summary": a.LineageSummary}
	}

	return json.Marshal(doc)
}

func ecsCategory(action string) string {
	switch action {
	case "Sensitive_File_Access":
		return "file"
	case "Network_Connection":
		return "network"
	case "Log_Tampering", "Ebpf_Tampering", "Perf_Event_Open":
		return "host"
	default:
		return "process"
	}
}

func ecsType(action string) string {
	switch action {
	case "Sensitive_File_Access":
		return "access"
	case "Process_Execution":
		return "start"
	case "Process_Injection":
		return "change"
	case "Network_Connection":
		return "connection"
	case "Log_Tampering", "Ebpf_Tampering":
		return "deletion"
	default:
		return "change"
	}
}

func ecsSeverity(sev string) int {
	switch sev {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

func ecsMitreURL(id string) string {
	if i := strings.IndexByte(id, '.'); i > 0 {
		return id[:i] + "/" + id[i+1:]
	}
	return id
}
