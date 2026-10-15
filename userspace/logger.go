package main

import (
	"bufio"
	"fmt"
	"io"
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
			if rl.bw != nil {
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

	if rl.degraded || rl.bw == nil {
		return len(p), nil // swallow; stdout already has it via io.MultiWriter
	}

	if rl.maxBytes > 0 && rl.currentSize+int64(len(p)) > rl.maxBytes {
		if err := rl.rotate(); err != nil {
			log.Printf("[logger] WARNING: rotation failed: %v (continuing to append)", err)
		}
	}

	n, err := rl.bw.Write(p)
	rl.currentSize += int64(n)
	if err != nil {
		log.Printf("[logger] WARNING: buffered write failed: %v", err)
	}
	return n, nil // never propagate file errors up to the ringbuf consumer loop
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
	if rl.bw != nil {
		rl.bw.Flush()
	}
	if rl.file != nil {
		return rl.file.Close()
	}
	return nil
}

// NewEnterpriseWriter returns a writer that fans every write out to both
// stdout (for foreground/systemd/journald capture) and the rotating file.
func NewEnterpriseWriter(path string, maxBytes int64, maxBackups int) (io.Writer, *RotatingLogger) {
	rl := NewRotatingLogger(path, maxBytes, maxBackups)
	return io.MultiWriter(os.Stdout, rl), rl
}
