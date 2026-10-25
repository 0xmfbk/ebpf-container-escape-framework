package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	flushInterval  = 100 * time.Millisecond
	writerBufBytes = 64 * 1024
)

// RotatingLogger is a minimal, dependency-free rotating file writer.
// Writes go through a buffered writer and are flushed on a timer rather
// than per-call, trading a bounded worst-case data-loss window (one flush
// interval, on an unclean crash) for far fewer write() syscalls under
// sustained event load.
type RotatingLogger struct {
	mu          sync.Mutex
	path        string
	maxBytes    int64
	maxBackups  int
	file        *os.File
	bw          *bufio.Writer
	currentSize int64
	degraded    bool // true if we couldn't open the target file; we keep running stdout-only
	retryAt     time.Time
	warnedOnce  bool // log the degraded transition once, not per event
	closed      bool

	flushTicker *time.Ticker
	stopFlush   chan struct{}
	stopped     sync.Once
}

// NewRotatingLogger opens (or creates) the log file at path. maxBackups
// controls how many historical files (path.1 .. path.N) are retained.
func NewRotatingLogger(path string, maxBytes int64, maxBackups int) *RotatingLogger {
	rl := &RotatingLogger{
		path:       path,
		maxBytes:   maxBytes,
		maxBackups: maxBackups,
		stopFlush:  make(chan struct{}),
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		log.Printf("[logger] WARNING: cannot create log directory %s: %v (file logging disabled, stdout only)", filepath.Dir(path), err)
		rl.degraded = true
		return rl
	}

	if err := rl.openCurrent(); err != nil {
		log.Printf("[logger] WARNING: cannot open log file %s: %v (file logging disabled, stdout only)", path, err)
		rl.degraded = true
		return rl
	}

	rl.flushTicker = time.NewTicker(flushInterval)
	go rl.flushLoop()

	return rl
}

func (rl *RotatingLogger) flushLoop() {
	for {
		select {
		case <-rl.flushTicker.C:
			rl.mu.Lock()
			if rl.bw != nil && !rl.closed {
				if err := rl.bw.Flush(); err != nil {
					log.Printf("[logger] WARNING: periodic flush failed: %v", err)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopFlush:
			return
		}
	}
}

func (rl *RotatingLogger) openCurrent() error {
	f, err := os.OpenFile(rl.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	rl.file = f
	rl.bw = bufio.NewWriterSize(f, writerBufBytes)
	rl.currentSize = info.Size()
	return nil
}

// Write implements io.Writer. Each call is treated as one record. We
// rotate *before* writing if the new record would push us over maxBytes.
func (rl *RotatingLogger) Write(p []byte) (int, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.bw == nil || rl.degraded {
		rl.tryRecoverLocked()
	}
	if rl.bw == nil || rl.degraded || rl.closed {
		return len(p), nil // swallow; stdout already has it via io.MultiWriter
	}

	if rl.maxBytes > 0 && rl.currentSize+int64(len(p)) > rl.maxBytes {
		if err := rl.rotate(); err != nil {
			log.Printf("[logger] WARNING: rotation failed: %v (will retry)", err)
			rl.degraded = true
			rl.retryAt = time.Now().Add(time.Second)
			return len(p), nil
		}
	}

	n, err := rl.bw.Write(p)
	rl.currentSize += int64(n)
	if err != nil {
		log.Printf("[logger] WARNING: buffered write failed: %v", err)
	}
	return n, nil // never propagate file errors up to the ringbuf consumer loop
}

// tryRecoverLocked attempts to re-open the log file after a mid-run
// failure (initial open failure, or a rotation that could not complete).
// Retries are rate-limited to once per second so a persistently broken
// target (full disk, lost permissions) cannot hot-loop the consumer.
// The degraded transition is logged once per outage, and recovery is
// logged so operators can see file alerting come back.
// Caller must hold rl.mu.
func (rl *RotatingLogger) tryRecoverLocked() {
	if rl.closed {
		return
	}
	now := time.Now()
	if now.Before(rl.retryAt) {
		return
	}
	rl.retryAt = now.Add(time.Second)
	if err := rl.openCurrent(); err != nil {
		if !rl.warnedOnce {
			log.Printf("[logger] WARNING: log file %s unavailable: %v (file alerting degraded, stdout only; retrying)", rl.path, err)
			rl.warnedOnce = true
		}
		return
	}
	rl.degraded = false
	if rl.warnedOnce {
		log.Printf("[logger] log file recovered: %s", rl.path)
	}
	rl.warnedOnce = false
}

// rotate flushes and closes the current file, shifts path.N -> path.N+1
// (dropping anything beyond maxBackups), then reopens a fresh current file.
// Caller must hold rl.mu.
func (rl *RotatingLogger) rotate() error {
	if rl.bw != nil {
		rl.bw.Flush()
	}
	if rl.file != nil {
		rl.file.Close()
		rl.file = nil
		rl.bw = nil
	}

	for i := rl.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", rl.path, i)
		dst := fmt.Sprintf("%s.%d", rl.path, i+1)
		if _, err := os.Stat(src); err == nil {
			if i+1 > rl.maxBackups {
				os.Remove(src)
			} else {
				os.Rename(src, dst)
			}
		}
	}

	if rl.maxBackups > 0 {
		if _, err := os.Stat(rl.path); err == nil {
			if err := os.Rename(rl.path, rl.path+".1"); err != nil {
				return err
			}
		}
	}

	return rl.openCurrent()
}

// Degraded reports whether file logging is currently unavailable (the
// initial open failed, or a rotation failed and recovery has not yet
// succeeded). Surfaced in the health line and on /metrics.
func (rl *RotatingLogger) Degraded() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.degraded
}

// Close flushes any buffered data, stops the flush goroutine, and closes
// the underlying file. Safe to call once; subsequent calls are no-ops.
func (rl *RotatingLogger) Close() error {
	rl.stopped.Do(func() {
		if rl.flushTicker != nil {
			rl.flushTicker.Stop()
		}
		close(rl.stopFlush)
	})

	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.closed = true
	if rl.bw != nil {
		rl.bw.Flush()
	}
	if rl.file != nil {
		return rl.file.Close()
	}
	return nil
}

// getWriter for the file sink is assembled in main.go: by default alerts
// are mirrored to stdout (io.MultiWriter) for journald/foreground capture;
// --quiet drops the mirror and writes the rotating file only.
