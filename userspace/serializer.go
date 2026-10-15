package main

import (
	"bytes"
	"strconv"
	"sync"
)

var bufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

func serializeAlert(a *SecurityAlert) []byte {
    buf := bufPool.Get().(*bytes.Buffer)
    buf.Reset()
    defer bufPool.Put(buf)

    buf.WriteString(`{"timestamp":"`)
    buf.WriteString(a.Timestamp)
    buf.WriteString(`","pid":`)
    buf.WriteString(strconv.FormatUint(uint64(a.PID), 10))
    buf.WriteString(`,"uid":`)
    buf.WriteString(strconv.FormatUint(uint64(a.UID), 10))
    buf.WriteString(`,"command":"`)
    writeEscaped(buf, a.Command)
    buf.WriteString(`","action":"`)
    writeEscaped(buf, a.Action)
    buf.WriteByte('"')
    
    // إظهار الـ target فقط إذا كان موجوداً وله قيمة حقيقية
    if a.Target != "" {
        buf.WriteString(`,"target":"`)
        writeEscaped(buf, a.Target)
        buf.WriteByte('"')
    }

    buf.WriteString(`,"severity":"`)
    buf.WriteString(a.Severity)
    buf.WriteString(`","mitre_id":"`)
    buf.WriteString(a.MitreID)
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

    out := make([]byte, buf.Len())
    copy(out, buf.Bytes())
    return out
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
