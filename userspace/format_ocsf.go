package main

import (
	"encoding/json"
	"strconv"
	"time"
)

type ocsfEncoder struct{}

func (ocsfEncoder) Name() string        { return "ocsf" }
func (ocsfEncoder) ContentType() string { return "application/json" }

func (ocsfEncoder) Encode(a *SecurityAlert) ([]byte, error) {
	t, err := time.Parse(time.RFC3339, a.Timestamp)
	if err != nil {
		t = time.Now().UTC()
	}

	actor := map[string]any{
		"process": map[string]any{
			"pid":            a.PID,
			"name":           a.Command,
			"parent_process": map[string]any{"pid": a.PPID},
		},
		"user": map[string]any{"uid": strconv.FormatUint(uint64(a.UID), 10)},
	}
	if a.ContainerID != "" {
		actor["process"].(map[string]any)["container_uid"] = a.ContainerID
	}

	doc := map[string]any{
		"class_uid":     2004,
		"class_name":    "Detection Finding",
		"category_uid":  2,
		"category_name": "Findings",
		"activity_id":   1,
		"activity_name": "Create",
		"type_uid":      200401,
		"time":          t.UnixMilli(),
		"severity_id":   ocsfSeverityID(a.Severity),
		"severity":      ocsfSeverityLabel(a.Severity),
		"message":       a.Action + " " + a.Target,
		"metadata": map[string]any{
			"version":  "1.3.0",
			"product":  map[string]any{"name": "ebpf-edr", "vendor_name": "0xmfbk"},
			"profiles": []string{"security_control"},
		},
		"finding_info": map[string]any{
			"title": a.Action,
			"uid":   a.MitreID + ":" + strconv.FormatUint(uint64(a.PID), 10),
			"types": []string{a.MitreTechnique},
			"analytic": map[string]any{
				"name":    "ebpf-edr",
				"type_id": 1,
				"type":    "Rule",
			},
		},
		"actor":  actor,
		"device": map[string]any{"type_id": 1, "type": "Server"},
		"attacks": []map[string]any{{
			"technique": map[string]any{
				"uid":  a.MitreID,
				"name": a.MitreTechnique,
			},
		}},
	}

	if a.ContainerID != "" {
		doc["container"] = map[string]any{
			"uid":  a.ContainerID,
			"name": a.Runtime,
		}
	}
	if a.DestIP != "" {
		doc["dst_endpoint"] = map[string]any{"ip": a.DestIP, "port": a.DestPort}
	}
	if a.LineageSummary != "" {
		doc["unmapped"] = map[string]any{"lineage_summary": a.LineageSummary}
	}

	return json.Marshal(doc)
}

func ocsfSeverityID(sev string) int {
	switch sev {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "INFO":
		return 1
	default:
		return 0
	}
}

func ocsfSeverityLabel(sev string) string {
	switch sev {
	case "CRITICAL":
		return "Critical"
	case "HIGH":
		return "High"
	case "MEDIUM":
		return "Medium"
	case "INFO":
		return "Informational"
	default:
		return "Unknown"
	}
}
