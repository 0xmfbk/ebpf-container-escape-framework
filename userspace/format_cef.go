package main

import (
	"bytes"
	"strconv"
	"time"
)

type cefEncoder struct{}

func (cefEncoder) Name() string        { return "cef" }
func (cefEncoder) ContentType() string { return "text/plain" }

func (cefEncoder) Encode(a *SecurityAlert) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString("CEF:0|ebpf-edr|ebpf-edr|2.6.0|")
	buf.WriteString(cefHeaderEscape(a.Action))
	buf.WriteByte('|')
	buf.WriteString(cefHeaderEscape(a.MitreTechnique))
	buf.WriteByte('|')
	buf.WriteString(strconv.Itoa(cefSeverity(a.Severity)))
	buf.WriteByte('|')

	buf.WriteString("rt=")
	buf.WriteString(time.Now().UTC().Format(time.RFC3339))

	buf.WriteString(" suser=")
	buf.WriteString(cefExtEscape(strconv.FormatUint(uint64(a.UID), 10)))

	buf.WriteString(" spid=")
	buf.WriteString(strconv.FormatUint(uint64(a.PID), 10))

	buf.WriteString(" proc=")
	buf.WriteString(cefExtEscape(a.Command))

	buf.WriteString(" cs1Label=MITRE_ID cs1=")
	buf.WriteString(cefExtEscape(a.MitreID))

	if a.Target != "" {
		buf.WriteString(" fname=")
		buf.WriteString(cefExtEscape(a.Target))
	}
	if a.ContainerID != "" {
		buf.WriteString(" cntrId=")
		buf.WriteString(cefExtEscape(a.ContainerID))
	}
	if a.DestIP != "" {
		buf.WriteString(" dst=")
		buf.WriteString(a.DestIP)
		buf.WriteString(" dpt=")
		buf.WriteString(strconv.FormatUint(uint64(a.DestPort), 10))
	}
	if a.LineageSummary != "" {
		buf.WriteString(" cs2Label=Lineage cs2=")
		buf.WriteString(cefExtEscape(a.LineageSummary))
	}

	return buf.Bytes(), nil
}

func cefSeverity(sev string) int {
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

func cefHeaderEscape(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '|', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n', '\r':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func cefExtEscape(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '=', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n', '\r':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
