package main

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"sync"
)

var bufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

func writeAlert(w io.Writer, a *SecurityAlert) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	buf.WriteString(`{"timestamp":"`)
	writeEscaped(buf, a.Timestamp)
	buf.WriteString(`","pid":`)
	buf.WriteString(strconv.FormatUint(uint64(a.PID), 10))
	buf.WriteString(`,"ppid":`)
	buf.WriteString(strconv.FormatUint(uint64(a.PPID), 10))
	buf.WriteString(`,"uid":`)
	buf.WriteString(strconv.FormatUint(uint64(a.UID), 10))
	buf.WriteString(`,"start_time_ns":`)
	buf.WriteString(strconv.FormatUint(a.StartTimeNs, 10))
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
	writeEscaped(buf, a.Severity)
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
	if a.CgroupPath != "" {
		buf.WriteString(`,"cgroup_path":"`)
		writeEscaped(buf, a.CgroupPath)
		buf.WriteByte('"')
	}
	if a.LineageSummary != "" {
		buf.WriteString(`,"lineage_summary":"`)
		writeEscaped(buf, a.LineageSummary)
		buf.WriteByte('"')
	}
	if len(a.Lineage) > 0 {
		buf.WriteString(`,"lineage":[`)
		for i, e := range a.Lineage {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(`{"pid":`)
			buf.WriteString(strconv.FormatUint(uint64(e.Pid), 10))
			buf.WriteString(`,"ppid":`)
			buf.WriteString(strconv.FormatUint(uint64(e.Ppid), 10))
			buf.WriteString(`,"comm":"`)
			writeEscaped(buf, e.Comm)
			buf.WriteByte('"')
			if e.Exe != "" {
				buf.WriteString(`,"exe":"`)
				writeEscaped(buf, e.Exe)
				buf.WriteByte('"')
			}
			buf.WriteString(`,"start_time_ns":`)
			buf.WriteString(strconv.FormatUint(e.StartTimeNs, 10))
			buf.WriteByte('}')
		}
		buf.WriteByte(']')
		if a.LineageTruncated {
			buf.WriteString(`,"lineage_truncated":true`)
		}
	}
	if a.AuxU16 != 0 {
		buf.WriteString(`,"aux_u16":`)
		buf.WriteString(strconv.FormatUint(uint64(a.AuxU16), 10))
	}
	if a.AuxU32 != 0 {
		buf.WriteString(`,"aux_u32":`)
		buf.WriteString(strconv.FormatUint(uint64(a.AuxU32), 10))
	}
	if a.AuxU64 != 0 {
		buf.WriteString(`,"aux_u64":`)
		buf.WriteString(strconv.FormatUint(a.AuxU64, 10))
	}
	if a.DestIP != "" {
		buf.WriteString(`,"dest_ip":"`)
		writeEscaped(buf, a.DestIP)
		buf.WriteString(`","dest_port":`)
		buf.WriteString(strconv.FormatUint(uint64(a.DestPort), 10))
	}
	buf.WriteString("}\n")

	_, _ = w.Write(buf.Bytes())
}

func writeEscaped(buf *bytes.Buffer, s string) {
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
				continue
			}
			buf.WriteRune(r)
		}
	}
}
