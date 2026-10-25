package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

// metricsServer exposes the daemon's health counters in Prometheus text
// format. Hand-rolled (no client_golang) to keep the binary dependency
// free; every value is read atomically so scrapes never contend with the
// event path. Read-only: counters and gauges only, no event payloads,
// no paths, no credentials.
type metricsServer struct {
	bind     string
	start    time.Time
	sink     func() SinkStats
	lineage  func() (size, capacity, hits, misses uint64)
	cgroup   func() (size, capacity uint64)
	queue    func() int
	degraded func() bool
}

func (m *metricsServer) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" && r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	body := m.render()
	w.Header().Set("Content-Type", metricsContentType)
	_, _ = io.WriteString(w, body)
}

// serve runs until the process exits. A metrics failure must never take
// detection down, so bind errors are logged and survived.
func (m *metricsServer) serve() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handler)
	srv := &http.Server{Addr: m.bind, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("[metrics] listening on %s", m.bind)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[metrics] server error: %v (continuing without metrics)", err)
	}
}

func escapeLabel(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

func (m *metricsServer) render() string {
	var b strings.Builder
	upSeconds := time.Since(m.start).Seconds()

	wf := func(name, help, typ string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	wg := func(name string, v float64) {
		fmt.Fprintf(&b, "%s %v\n", name, v)
	}
	wl := func(name, label, val string, v uint64) {
		fmt.Fprintf(&b, "%s{%s=\"%s\"} %d\n", name, label, escapeLabel(val), v)
	}

	wf("ebpf_edr_up", "1 while the sensor process is running.", "gauge")
	wg("ebpf_edr_up", 1)

	wf("ebpf_edr_build_info", "Build metadata; the value is always 1.", "gauge")
	fmt.Fprintf(&b, "ebpf_edr_build_info{version=\"%s\",event_version=\"%d\"} 1\n",
		daemonVersion, eventVersion)

	wf("ebpf_edr_uptime_seconds", "Seconds since the sensor attached.", "gauge")
	wg("ebpf_edr_uptime_seconds", upSeconds)

	wf("ebpf_edr_events_total", "Alerts emitted, by action.", "counter")
	for id := uint32(1); id < ActionMaxID; id++ {
		if name, ok := actionNames[id]; ok {
			wl("ebpf_edr_events_total", "action", name, atomic.LoadUint64(&actionCounts[id]))
		}
	}

	wf("ebpf_edr_events_received_total", "Events read from the ring buffer.", "counter")
	wg("ebpf_edr_events_received_total", float64(atomic.LoadUint64(&stats.eventsReceived)))
	wf("ebpf_edr_events_dropped_total", "Events dropped: ring buffer or channel full.", "counter")
	wg("ebpf_edr_events_dropped_total", float64(atomic.LoadUint64(&stats.eventsDropped)))
	wf("ebpf_edr_events_rate_limited_total", "Events suppressed by the per-action token bucket.", "counter")
	wg("ebpf_edr_events_rate_limited_total", float64(atomic.LoadUint64(&stats.eventsRateLim)))
	wf("ebpf_edr_parse_errors_total", "Malformed ring buffer records.", "counter")
	wg("ebpf_edr_parse_errors_total", float64(atomic.LoadUint64(&stats.parseErrors)))
	wf("ebpf_edr_version_mismatch_total", "Events with an unexpected wire version.", "counter")
	wg("ebpf_edr_version_mismatch_total", float64(atomic.LoadUint64(&stats.versionMismatch)))
	wf("ebpf_edr_ringbuf_read_errors_total", "Ring buffer read errors (retried).", "counter")
	wg("ebpf_edr_ringbuf_read_errors_total", float64(atomic.LoadUint64(&stats.ringbufReadErrs)))
	wf("ebpf_edr_reloads_total", "Successful SIGHUP config reloads.", "counter")
	wg("ebpf_edr_reloads_total", float64(atomic.LoadUint64(&stats.reloads)))
	wf("ebpf_edr_reload_failures_total", "Rejected SIGHUP config reloads.", "counter")
	wg("ebpf_edr_reload_failures_total", float64(atomic.LoadUint64(&stats.reloadFails)))
	wf("ebpf_edr_sensor_heartbeats_total", "Synthetic Sensor_Heartbeat alerts emitted.", "counter")
	wg("ebpf_edr_sensor_heartbeats_total", float64(atomic.LoadUint64(&sensorHeartbeats)))

	wf("ebpf_edr_event_queue", "Events waiting in the userspace channel.", "gauge")
	wg("ebpf_edr_event_queue", float64(m.queue()))

	wf("ebpf_edr_lineage_cache_entries", "Process lineage cache entries.", "gauge")
	ls, lc, lh, lm := m.lineage()
	wg("ebpf_edr_lineage_cache_entries", float64(ls))
	wf("ebpf_edr_lineage_cache_capacity", "Process lineage cache capacity.", "gauge")
	wg("ebpf_edr_lineage_cache_capacity", float64(lc))
	wf("ebpf_edr_lineage_cache_hits_total", "Lineage cache hits.", "counter")
	wg("ebpf_edr_lineage_cache_hits_total", float64(lh))
	wf("ebpf_edr_lineage_cache_misses_total", "Lineage cache misses.", "counter")
	wg("ebpf_edr_lineage_cache_misses_total", float64(lm))

	cs, cc := m.cgroup()
	wf("ebpf_edr_cgroup_cache_entries", "Cgroup path cache entries.", "gauge")
	wg("ebpf_edr_cgroup_cache_entries", float64(cs))
	wf("ebpf_edr_cgroup_cache_capacity", "Cgroup path cache capacity.", "gauge")
	wg("ebpf_edr_cgroup_cache_capacity", float64(cc))

	st := m.sink()
	wf("ebpf_edr_sink_sent_total", "Alerts handed to the output transport.", "counter")
	wg("ebpf_edr_sink_sent_total", float64(st.Sent))
	wf("ebpf_edr_sink_failed_total", "Failed transport deliveries (after retries).", "counter")
	wg("ebpf_edr_sink_failed_total", float64(st.Failed))
	wf("ebpf_edr_sink_dropped_total", "Alerts dropped (queue full, circuit open, post-close).", "counter")
	wg("ebpf_edr_sink_dropped_total", float64(st.Dropped))
	wf("ebpf_edr_sink_retries_total", "Transport delivery retries.", "counter")
	wg("ebpf_edr_sink_retries_total", float64(st.Retries))
	wf("ebpf_edr_sink_queue", "Alerts queued for the output transport.", "gauge")
	wg("ebpf_edr_sink_queue", float64(st.QueueDepth))
	wf("ebpf_edr_sink_circuit_open", "1 while the output circuit breaker is open.", "gauge")
	if st.CircuitOpen {
		wg("ebpf_edr_sink_circuit_open", 1)
	} else {
		wg("ebpf_edr_sink_circuit_open", 0)
	}

	wf("ebpf_edr_logging_degraded", "1 while file logging is unavailable (stdout-only).", "gauge")
	if m.degraded() {
		wg("ebpf_edr_logging_degraded", 1)
	} else {
		wg("ebpf_edr_logging_degraded", 0)
	}

	return b.String()
}
