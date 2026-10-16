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
		{"sizeof", unsafe.Sizeof(event_t{}), 208},
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
		{"off_aux_u16", unsafe.Offsetof(event_t{}.AuxU16), 190},
		{"off_aux_u64", unsafe.Offsetof(event_t{}.AuxU64), 192},
		{"off_aux_u32", unsafe.Offsetof(event_t{}.AuxU32), 200},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestEventVersion(t *testing.T) {
	if eventVersion != 3 {
		t.Fatalf("eventVersion = %d, want 3", eventVersion)
	}
}
