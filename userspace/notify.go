package main

import (
	"net"
	"os"
	"path/filepath"
	"time"
)

// sdNotify sends a message to systemd's NOTIFY_SOCKET (sd_notify(3)).
// Used with Type=notify + WatchdogSec in ebpf-edr.service so a hung or
// crashed sensor is detected and restarted by the init system. It is a
// no-op when NOTIFY_SOCKET is absent (foreground runs, containers), so
// the same binary runs identically under systemd, Docker and Kubernetes.
func sdNotify(msg string) {
	sockPath := os.Getenv("NOTIFY_SOCKET")
	if sockPath == "" {
		return
	}
	// Abstract sockets are addressed with a leading NUL byte.
	if sockPath[0] == '@' {
		sockPath = "\x00" + sockPath[1:]
	}
	conn, err := net.DialTimeout("unixgram", sockPath, time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(msg))
}

// touchHeartbeat refreshes a timestamp file that external watchdogs (the
// Kubernetes exec liveness probe, cron-based checks) can test for age.
// Best-effort by design: a read-only or missing directory must never
// impair detection, callers ignore the error.
func touchHeartbeat(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(time.Now().UTC().Format(time.RFC3339))
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}
