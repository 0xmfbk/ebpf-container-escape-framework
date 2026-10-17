package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	syslogFacilityAudit = 13
	syslogAppName       = "ebpf-edr"
)

type syslogTransport struct {
	network string
	address string
	tag     string
	tlsCA   string

	mu   sync.Mutex
	conn net.Conn
}

func newSyslogTransport(network, address, tag, tlsCA string) (*syslogTransport, error) {
	if network != "udp" && network != "tcp" && network != "tls" {
		return nil, fmt.Errorf("syslog network must be udp|tcp|tls, got %q", network)
	}
	if address == "" {
		return nil, fmt.Errorf("syslog address is required")
	}
	if tag == "" {
		tag = syslogAppName
	}
	t := &syslogTransport{network: network, address: address, tag: tag, tlsCA: tlsCA}
	if err := t.connect(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *syslogTransport) Name() string { return "syslog:" + t.network }

func (t *syslogTransport) connect() error {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	switch t.network {
	case "udp":
		c, err := dialer.Dial("udp", t.address)
		if err != nil {
			return err
		}
		t.conn = c
	case "tcp":
		c, err := dialer.Dial("tcp", t.address)
		if err != nil {
			return err
		}
		t.conn = c
	case "tls":
		cfg := &tls.Config{ServerName: hostPart(t.address)}
		if t.tlsCA != "" {
			pem, err := os.ReadFile(t.tlsCA)
			if err != nil {
				return fmt.Errorf("read syslog tls_ca: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return fmt.Errorf("syslog tls_ca: no certificates parsed")
			}
			cfg.RootCAs = pool
		}
		c, err := tls.DialWithDialer(dialer, "tcp", t.address, cfg)
		if err != nil {
			return err
		}
		t.conn = c
	}
	return nil
}

func (t *syslogTransport) SendBatch(ctx context.Context, batch []Envelope) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		if err := t.connect(); err != nil {
			return err
		}
	}
	for _, env := range batch {
		frame := t.frame(env)
		if _, err := t.conn.Write(frame); err != nil {
			_ = t.conn.Close()
			t.conn = nil
			return err
		}
	}
	return nil
}

func (t *syslogTransport) frame(env Envelope) []byte {
	pri := syslogFacilityAudit*8 + syslogSeverity(env.Severity)
	ts := env.Timestamp
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}
	host := env.Host
	if host == "" {
		host = "-"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<%d>1 %s %s %s - - - ", pri, ts, host, t.tag)
	b.Write(env.Payload)
	b.WriteByte('\n')
	return []byte(b.String())
}

func (t *syslogTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		err := t.conn.Close()
		t.conn = nil
		return err
	}
	return nil
}

func syslogSeverity(sev string) int {
	switch sev {
	case "CRITICAL":
		return 2
	case "HIGH":
		return 3
	case "MEDIUM":
		return 4
	case "INFO":
		return 6
	default:
		return 6
	}
}

func hostPart(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
