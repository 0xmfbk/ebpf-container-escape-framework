package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"unsafe"
)

// FuzzDecodeEvent feeds arbitrary bytes into the binary event decoder.
func FuzzDecodeEvent(f *testing.F) {
	f.Add(make([]byte, eventSize))
	f.Add(bytes.Repeat([]byte{0xff}, eventSize))
	seed := make([]byte, eventSize)
	seed[16] = 3
	seed[20] = 3
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < eventSize {
			return
		}
		var re rawEvent
		copy((*[eventSize]byte)(unsafe.Pointer(&re.data[0]))[:], data[:eventSize])
		ev := (*event_t)(unsafe.Pointer(&re.data[0]))

		_ = ev.CgroupID
		_ = ev.StartTimeNs
		_ = ev.Version
		_ = ev.ActionID
		_ = ev.Pid
		_ = ev.Ppid
		_ = ev.Uid
		_ = ev.Flags
		_ = ev.DestPort
		_ = ev.AuxU16
		_ = ev.AuxU32
		_ = ev.AuxU64

		comm := cstr(ev.Comm[:])
		fname := cstr(ev.Filename[:])

		if action, ok := actionNames[ev.ActionID]; ok {
			_, _, _ = calculateSeverity(DefaultConfig(), action, comm, fname, ev.DestPort, ev.AuxU32)
		}
	})
}

// FuzzSerializeAlert feeds arbitrary strings into the JSON serializer.
func FuzzSerializeAlert(f *testing.F) {
	f.Add("2026-01-01T00:00:00Z", "cat", "/etc/shadow", uint16(0))
	f.Add("", "", "", uint16(4444))
	f.Add("\x00\x01\x02", "a\"b\\c\nd", "/tmp/\xe2\x9c\x93", uint16(65535))

	f.Fuzz(func(t *testing.T, ts, comm, target string, port uint16) {
		a := &SecurityAlert{
			Timestamp:      ts,
			PID:            1234,
			PPID:           1,
			UID:            0,
			StartTimeNs:    1_000_000_000,
			Command:        comm,
			Action:         "Sensitive_File_Access",
			Target:         target,
			Severity:       "HIGH",
			MitreID:        "T1003.008",
			MitreTechnique: "OS Credential Dumping",
			CgroupID:       42,
			Runtime:        "host",
			DestPort:       port,
		}
		payload, err := jsonEncoder{}.Encode(a)
		if err != nil {
			t.Fatalf("json encode error: %v", err)
		}

		var out map[string]any
		if err := json.Unmarshal(payload, &out); err != nil {
			t.Fatalf("invalid JSON: %v\nraw: %q", err, string(payload))
		}
	})
}

// FuzzConfigParse feeds arbitrary bytes into LoadConfig + Validate.
func FuzzConfigParse(f *testing.F) {
	f.Add([]byte("mode = \"audit\"\n"))
	f.Add([]byte(""))
	f.Add([]byte("this is = not valid toml"))
	f.Add([]byte("[rates]\nevents_per_sec = -1\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp, err := os.CreateTemp("", "fuzzcfg-*.toml")
		if err != nil {
			t.Skip()
		}
		name := tmp.Name()
		defer os.Remove(name)
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			t.Skip()
		}
		tmp.Close()

		cfg, err := LoadConfig(name)
		if err == nil {
			_ = cfg.Validate()
		}
	})
}

func FuzzECSEncode(f *testing.F) {
	f.Add("2026-01-01T00:00:00Z", "cat", "/etc/shadow", uint16(0), "HIGH", "T1003.008")
	f.Add("", "", "", uint16(0), "", "")
	f.Add("\x00\x01", "\xff", "\x7f", uint16(65535), "CRITICAL", "T1611")

	f.Fuzz(func(t *testing.T, ts, cmd, target string, port uint16, sev, mitre string) {
		a := &SecurityAlert{
			Timestamp: ts, Command: cmd, Target: target, DestPort: port,
			Severity: sev, MitreID: mitre, Action: "Sensitive_File_Access",
		}
		out, err := ecsEncoder{}.Encode(a)
		if err != nil {
			t.Fatalf("ecs encode error: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("ecs invalid JSON: %v\nraw: %q", err, string(out))
		}
	})
}

func FuzzOCSFEncode(f *testing.F) {
	f.Add("2026-01-01T00:00:00Z", "cat", "/etc/shadow", uint16(0), "HIGH", "T1003.008")
	f.Add("", "", "", uint16(0), "", "")
	f.Add("invalid-time", "\x01", "\x02", uint16(1), "CRITICAL", "T1611")

	f.Fuzz(func(t *testing.T, ts, cmd, target string, port uint16, sev, mitre string) {
		a := &SecurityAlert{
			Timestamp: ts, Command: cmd, Target: target, DestPort: port,
			Severity: sev, MitreID: mitre, Action: "Sensitive_File_Access",
		}
		out, err := ocsfEncoder{}.Encode(a)
		if err != nil {
			t.Fatalf("ocsf encode error: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("ocsf invalid JSON: %v\nraw: %q", err, string(out))
		}
	})
}

func FuzzCEFEncode(f *testing.F) {
	f.Add("2026-01-01T00:00:00Z", "cat", "/etc/shadow", uint16(0), "HIGH", "T1003.008")
	f.Add("", "", "", uint16(0), "", "")
	f.Add("a|b", "c=d", "e\\f", uint16(1), "CRITICAL", "x\ny")

	f.Fuzz(func(t *testing.T, ts, cmd, target string, port uint16, sev, mitre string) {
		a := &SecurityAlert{
			Timestamp: ts, Command: cmd, Target: target, DestPort: port,
			Severity: sev, MitreID: mitre, Action: "Sensitive_File_Access",
		}
		out, err := cefEncoder{}.Encode(a)
		if err != nil {
			t.Fatalf("cef encode error: %v", err)
		}
		if len(out) == 0 {
			t.Fatal("cef produced empty output")
		}
		if string(out[:6]) != "CEF:0|" {
			t.Fatalf("cef missing prefix: %q", string(out))
		}
	})
}
