package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type webhookTransport struct {
	url         string
	authHeader  string
	contentType string
	batchStyle  string // "json" | "ndjson"
	splunkHEC   bool
	insecureTLS bool
	timeout     time.Duration
	client      *http.Client
}

func newWebhookTransport(url, authHeader, contentType, batchStyle string, splunkHEC, insecureTLS bool, timeout time.Duration) (*webhookTransport, error) {
	if url == "" {
		return nil, fmt.Errorf("webhook url is required")
	}
	if contentType == "" {
		contentType = "application/json"
	}
	switch batchStyle {
	case "", "ndjson":
		batchStyle = "ndjson"
	case "json":
	default:
		return nil, fmt.Errorf("webhook batch_style must be json|ndjson, got %q", batchStyle)
	}
	if splunkHEC {
		batchStyle = "ndjson"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	tr := &http.Transport{
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecureTLS,
		},
	}
	return &webhookTransport{
		url:         url,
		authHeader:  os.ExpandEnv(authHeader),
		contentType: contentType,
		batchStyle:  batchStyle,
		splunkHEC:   splunkHEC,
		insecureTLS: insecureTLS,
		timeout:     timeout,
		client: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
	}, nil
}

func (t *webhookTransport) Name() string { return "webhook" }

func (t *webhookTransport) SendBatch(ctx context.Context, batch []Envelope) error {
	body := t.encodeBody(batch)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, os.ExpandEnv(t.url), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", t.contentType)
	req.Header.Set("User-Agent", "ebpf-edr/2.6.0")
	if t.authHeader != "" {
		if strings.HasPrefix(t.authHeader, "Bearer ") ||
			strings.HasPrefix(t.authHeader, "Splunk ") ||
			strings.HasPrefix(t.authHeader, "Basic ") {
			req.Header.Set("Authorization", t.authHeader)
		} else {
			req.Header.Set("Authorization", "Bearer "+t.authHeader)
		}
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slurp, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook HTTP %d: %s", resp.StatusCode, string(slurp))
	}
	return nil
}

func (t *webhookTransport) encodeBody(batch []Envelope) []byte {
	var buf bytes.Buffer
	if t.batchStyle == "json" && !t.splunkHEC {
		buf.WriteByte('[')
		for i, env := range batch {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.Write(env.Payload)
		}
		buf.WriteByte(']')
		return buf.Bytes()
	}
	// ndjson (also used for Splunk HEC)
	for i, env := range batch {
		if i > 0 {
			buf.WriteByte('\n')
		}
		if t.splunkHEC {
			buf.WriteString(`{"event":`)
			buf.Write(env.Payload)
			buf.WriteString(`,"source":"ebpf-edr","sourcetype":"ebpf:edr:json"`)
			if env.Host != "" {
				buf.WriteString(`,"host":`)
				writeEscapedJSONString(&buf, env.Host)
			}
			buf.WriteByte('}')
		} else {
			buf.Write(env.Payload)
		}
	}
	return buf.Bytes()
}

func (t *webhookTransport) Close() error {
	if t.client != nil {
		t.client.CloseIdleConnections()
	}
	return nil
}

func writeEscapedJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	writeEscaped(buf, s)
	buf.WriteByte('"')
}
