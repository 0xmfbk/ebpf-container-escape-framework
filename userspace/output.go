package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

type SinkStats struct {
	Sent        uint64
	Failed      uint64
	Dropped     uint64
	Retries     uint64
	QueueDepth  int
	CircuitOpen bool
}

// Sink receives alerts from the consumer goroutine. Submit must never block.
type Sink interface {
	Submit(a *SecurityAlert)
	Flush(timeout time.Duration) error
	Close() error
	Stats() SinkStats
	Describe() string
}

// Envelope carries one encoded event plus metadata for transports that
// need more than the raw payload (syslog priority, hostname, etc).
type Envelope struct {
	Payload   []byte
	Severity  string
	Timestamp string
	Host      string
}

// Transport actually ships envelopes. Implementations: syslogTransport,
// webhookTransport.
type Transport interface {
	SendBatch(ctx context.Context, items []Envelope) error
	Close() error
	Name() string
}

// ---------- file / stdout sink ----------

type fileSink struct {
	enc          Encoder
	w            io.Writer
	written      uint64
	encodeFailed uint64
	writeFailed  uint64
}

func newFileSink(enc Encoder, w io.Writer) *fileSink {
	return &fileSink{enc: enc, w: w}
}

func (s *fileSink) Submit(a *SecurityAlert) {
	payload, err := s.enc.Encode(a)
	if err != nil {
		atomic.AddUint64(&s.encodeFailed, 1)
		return
	}
	// Preserve line-delimited output.
	maxInt := int(^uint(0) >> 1)
	if len(payload) >= maxInt {
		atomic.AddUint64(&s.encodeFailed, 1)
		return
	}
	line := make([]byte, 0, len(payload)+1)
	line = append(line, payload...)
	line = append(line, '\n')
	if _, err := s.w.Write(line); err != nil {
		atomic.AddUint64(&s.writeFailed, 1)
		return
	}
	atomic.AddUint64(&s.written, 1)
}

func (s *fileSink) Flush(timeout time.Duration) error { return nil }
func (s *fileSink) Close() error                      { return nil }
func (s *fileSink) Stats() SinkStats {
	return SinkStats{
		Sent:   atomic.LoadUint64(&s.written),
		Failed: atomic.LoadUint64(&s.encodeFailed) + atomic.LoadUint64(&s.writeFailed),
	}
}
func (s *fileSink) Describe() string { return "file[" + s.enc.Name() + "]" }

// ---------- network sink (syslog / webhook) ----------

const (
	defaultQueueSize        = 10000
	defaultWorkers          = 4
	defaultBatchSize        = 100
	defaultFlushInterval    = 2 * time.Second
	defaultMaxRetries       = 3
	defaultRetryBase        = 100 * time.Millisecond
	defaultCircuitThreshold = int32(5)
	defaultCircuitCooldown  = 30 * time.Second
	maxBatchBytes           = 512 * 1024
)

type NetworkSinkConfig struct {
	Workers          int
	BatchSize        int
	FlushInterval    time.Duration
	MaxRetries       int
	RetryBase        time.Duration
	CircuitThreshold int32
	CircuitCooldown  time.Duration
}

func defaultNetworkSinkConfig() NetworkSinkConfig {
	return NetworkSinkConfig{
		Workers:          defaultWorkers,
		BatchSize:        defaultBatchSize,
		FlushInterval:    defaultFlushInterval,
		MaxRetries:       defaultMaxRetries,
		RetryBase:        defaultRetryBase,
		CircuitThreshold: defaultCircuitThreshold,
		CircuitCooldown:  defaultCircuitCooldown,
	}
}

type networkSink struct {
	enc       Encoder
	transport Transport
	queue     chan Envelope
	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once

	cfg  NetworkSinkConfig
	host string

	sent    uint64
	failed  uint64
	dropped uint64
	retries uint64

	consecutive   atomic.Int32
	circuitOpen   atomic.Bool
	resetPending  atomic.Bool // a cooldown reset goroutine is scheduled
	closed        atomic.Bool
	inFlight      atomic.Int64
	lastErrLog    atomic.Int64 // unix nanos of last "delivery failing" log
}

func newNetworkSink(enc Encoder, transport Transport, cfg NetworkSinkConfig) *networkSink {
	host, _ := getHostname()
	s := &networkSink{
		enc:       enc,
		transport: transport,
		queue:     make(chan Envelope, defaultQueueSize),
		done:      make(chan struct{}),
		cfg:       cfg,
		host:      host,
	}
	for i := 0; i < cfg.Workers; i++ {
		s.wg.Add(1)
		go s.worker()
	}
	return s
}

func (s *networkSink) Submit(a *SecurityAlert) {
	// Post-Close submits are counted as dropped instead of silently
	// piling up in a channel whose workers have exited.
	if s.closed.Load() {
		atomic.AddUint64(&s.dropped, 1)
		return
	}
	if s.circuitOpen.Load() {
		atomic.AddUint64(&s.dropped, 1)
		return
	}
	payload, err := s.enc.Encode(a)
	if err != nil {
		atomic.AddUint64(&s.failed, 1)
		return
	}
	env := Envelope{Payload: payload, Severity: a.Severity, Timestamp: a.Timestamp, Host: s.host}
	select {
	case s.queue <- env:
	default:
		atomic.AddUint64(&s.dropped, 1)
	}
}

func (s *networkSink) worker() {
	defer s.wg.Done()
	var batch []Envelope
	var total int

	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.inFlight.Add(int64(len(batch)))
		s.deliver(batch)
		s.inFlight.Add(-int64(len(batch)))
		batch = batch[:0]
		total = 0
	}

	timer := time.NewTimer(s.cfg.FlushInterval)
	defer timer.Stop()

	for {
		select {
		case <-s.done:
			// Drain for up to 3 seconds, then force-flush.
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				select {
				case env, ok := <-s.queue:
					if !ok {
						flush()
						return
					}
					batch = append(batch, env)
					total += len(env.Payload)
					if len(batch) >= s.cfg.BatchSize || total >= maxBatchBytes {
						flush()
					}
				default:
					flush()
					return
				}
			}
			flush()
			return
		case env, ok := <-s.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, env)
			total += len(env.Payload)
			if len(batch) >= s.cfg.BatchSize || total >= maxBatchBytes {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(s.cfg.FlushInterval)
			}
		case <-timer.C:
			flush()
			timer.Reset(s.cfg.FlushInterval)
		}
	}
}

func (s *networkSink) deliver(batch []Envelope) {
	ctx := context.Background()
	delay := s.cfg.RetryBase

	for attempt := 0; attempt < s.cfg.MaxRetries; attempt++ {
		if s.circuitOpen.Load() {
			atomic.AddUint64(&s.dropped, uint64(len(batch)))
			return
		}
		err := s.transport.SendBatch(ctx, batch)
		if err == nil {
			atomic.AddUint64(&s.sent, uint64(len(batch)))
			s.consecutive.Store(0)
			return
		}
		if attempt < s.cfg.MaxRetries-1 {
			atomic.AddUint64(&s.retries, 1)
			time.Sleep(delay)
			delay *= 2
		}
	}

	// Persistent transport failures were previously invisible outside the
	// periodic health line; surface them (rate-limited to once per 30s).
	now := time.Now().UnixNano()
	last := s.lastErrLog.Load()
	if now-last > int64(30*time.Second) && s.lastErrLog.CompareAndSwap(last, now) {
		log.Printf("[sink] transport %s delivery failing: %v (see sink_* health counters)", s.transport.Name(), err)
	}

	atomic.AddUint64(&s.failed, 1)
	atomic.AddUint64(&s.dropped, uint64(len(batch)))
	if s.consecutive.Add(1) >= s.cfg.CircuitThreshold {
		// Open the breaker at most once per outage and schedule exactly
		// one cooldown reset; overlapping resets previously could close
		// the breaker early or clobber fresh failure counts.
		if s.circuitOpen.CompareAndSwap(false, true) && s.resetPending.CompareAndSwap(false, true) {
			go func() {
				time.Sleep(s.cfg.CircuitCooldown)
				s.circuitOpen.Store(false)
				s.consecutive.Store(0)
				s.resetPending.Store(false)
			}()
		}
	}
}

// Flush blocks until the queue is empty and no batch is mid-delivery,
// or the timeout expires. It reports an error (with what is still
// outstanding) instead of always claiming success.
func (s *networkSink) Flush(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if len(s.queue) == 0 && s.inFlight.Load() == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("%d queued, %d in flight after %v", len(s.queue), s.inFlight.Load(), timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *networkSink) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.done)
		done := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
		}
		err = s.transport.Close()
	})
	return err
}

func (s *networkSink) Stats() SinkStats {
	return SinkStats{
		Sent:        atomic.LoadUint64(&s.sent),
		Failed:      atomic.LoadUint64(&s.failed),
		Dropped:     atomic.LoadUint64(&s.dropped),
		Retries:     atomic.LoadUint64(&s.retries),
		QueueDepth:  len(s.queue),
		CircuitOpen: s.circuitOpen.Load(),
	}
}

func (s *networkSink) Describe() string {
	return fmt.Sprintf("network[%s/%s]", s.transport.Name(), s.enc.Name())
}
