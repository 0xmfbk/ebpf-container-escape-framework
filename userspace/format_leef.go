package main

import (
	"bytes"
	"strconv"
	"time"
)

type leefEncoder struct{}

func (leefEncoder) Name() string        { return "leef" }
func (leefEncoder) ContentType() string { return "text/plain" }

func (leefEncoder) Encode(a *SecurityAlert) ([]byte, error) {
	// LEEF 2.0 with '^' (0x5E) as attribute delimiter.
	var buf bytes.Buffer
	buf.WriteString("LEEF:2.0|ebpf-edr|ebpf-edr|2.6.0|")
	buf.WriteString(leefEscape(a.Action))
	buf.WriteByte('|')
	buf.WriteByte('^')
	buf.WriteByte('|')

	writeAttr := func(k, v string) {
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(leefEscape(v))
	}

	first := true
	sep := func() {
		if !first {
			buf.WriteByte('^')
		}
		first = false
	}

	sep()
	writeAttr("devTime", time.Now().UTC().Format(time.RFC3339))
	sep()
	writeAttr("sev", strconv.Itoa(leefSeverity(a.Severity)))
	sep()
	writeAttr("pid", strconv.FormatUint(uint64(a.PID), 10))
	sep()
	writeAttr("ppid", strconv.FormatUint(uint64(a.PPID), 10))
	sep()
	writeAttr("usrName", strconv.FormatUint(uint64(a.UID), 10))
	sep()
	writeAttr("proc", a.Command)
	sep()
	writeAttr("mitreId", a.MitreID)
	if a.Target != "" {
		sep()
		writeAttr("target", a.Target)
	}
	if a.ContainerID != "" {
		sep()
		writeAttr("containerId", a.ContainerID)
	}
	if a.DestIP != "" {
		sep()
		writeAttr("dst", a.DestIP)
		sep()
		writeAttr("dpt", strconv.FormatUint(uint64(a.DestPort), 10))
	}
	if a.LineageSummary != "" {
		sep()
		writeAttr("lineage", a.LineageSummary)
	}

	return buf.Bytes(), nil
}

func leefSeverity(sev string) int {
	switch sev {
	case "CRITICAL":
		return 10
	case "HIGH":
		return 8
	case "MEDIUM":
		return 5
	case "INFO":
		return 3
	default:
		return 0
	}
}

func leefEscape(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '^', '|', '=', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n', '\r', '\t':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
