package main

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// metrics are written in the Prometheus text exposition format (version
// 0.0.4) with the standard library.
type metrics struct {
	mu        sync.Mutex
	requests  map[[2]string]uint64 // {endpoint, code}
	durations map[string]*histogram
	bytesIn   map[string]uint64
	bytesOut  map[string]uint64
	signed    map[string]uint64 // by API key name
	limited   map[string]uint64 // by API key name
	authFail  uint64
	busy      uint64
	inFlight  int64
	version   string
	goVersion string
}

var durationBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

type histogram struct {
	counts []uint64 // per bucket, not cumulative
	sum    float64
	count  uint64
}

func newMetrics(version, goVersion string) *metrics {
	return &metrics{
		requests: map[[2]string]uint64{}, durations: map[string]*histogram{},
		bytesIn: map[string]uint64{}, bytesOut: map[string]uint64{},
		signed: map[string]uint64{}, limited: map[string]uint64{},
		version: version, goVersion: goVersion,
	}
}

func (m *metrics) observe(endpoint string, code int, d time.Duration, in, out int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[[2]string{endpoint, strconv.Itoa(code)}]++
	h := m.durations[endpoint]
	if h == nil {
		h = &histogram{counts: make([]uint64, len(durationBuckets))}
		m.durations[endpoint] = h
	}
	s := d.Seconds()
	for i, ub := range durationBuckets {
		if s <= ub {
			h.counts[i]++
			break
		}
	}
	h.sum += s
	h.count++
	m.bytesIn[endpoint] += uint64(max(in, 0))
	m.bytesOut[endpoint] += uint64(max(out, 0))
}

func (m *metrics) add(field *uint64) {
	m.mu.Lock()
	*field++
	m.mu.Unlock()
}

func (m *metrics) addKey(field map[string]uint64, key string) {
	m.mu.Lock()
	field[key]++
	m.mu.Unlock()
}

func (m *metrics) flight(delta int64) {
	m.mu.Lock()
	m.inFlight += delta
	m.mu.Unlock()
}

// write writes every metric, families and series in a stable order.
func (m *metrics) write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	family := func(name, typ, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	family("sealsvc_build_info", "gauge", "Version of sealsvc and of Go it was built with.")
	fmt.Fprintf(w, "sealsvc_build_info{version=%s,goversion=%s} 1\n", quote(m.version), quote(m.goVersion))

	family("sealsvc_requests_total", "counter", "Requests by endpoint and HTTP status code.")
	reqKeys := make([][2]string, 0, len(m.requests))
	for k := range m.requests {
		reqKeys = append(reqKeys, k)
	}
	slices.SortFunc(reqKeys, func(a, b [2]string) int { return strings.Compare(a[0]+"\x00"+a[1], b[0]+"\x00"+b[1]) })
	for _, k := range reqKeys {
		fmt.Fprintf(w, "sealsvc_requests_total{endpoint=%s,code=%s} %d\n", quote(k[0]), quote(k[1]), m.requests[k])
	}

	family("sealsvc_request_duration_seconds", "histogram", "Time to answer a request, by endpoint.")
	for _, ep := range sortedKeys(m.durations) {
		h := m.durations[ep]
		var cum uint64
		for i, ub := range durationBuckets {
			cum += h.counts[i]
			fmt.Fprintf(w, "sealsvc_request_duration_seconds_bucket{endpoint=%s,le=%s} %d\n", quote(ep), quote(strconv.FormatFloat(ub, 'g', -1, 64)), cum)
		}
		fmt.Fprintf(w, "sealsvc_request_duration_seconds_bucket{endpoint=%s,le=\"+Inf\"} %d\n", quote(ep), h.count)
		fmt.Fprintf(w, "sealsvc_request_duration_seconds_sum{endpoint=%s} %s\n", quote(ep), strconv.FormatFloat(h.sum, 'g', -1, 64))
		fmt.Fprintf(w, "sealsvc_request_duration_seconds_count{endpoint=%s} %d\n", quote(ep), h.count)
	}

	counterByLabel := func(name, label, help string, vals map[string]uint64) {
		family(name, "counter", help)
		for _, k := range sortedKeys(vals) {
			fmt.Fprintf(w, "%s{%s=%s} %d\n", name, label, quote(k), vals[k])
		}
	}
	counterByLabel("sealsvc_request_bytes_total", "endpoint", "Request body bytes read, by endpoint.", m.bytesIn)
	counterByLabel("sealsvc_response_bytes_total", "endpoint", "Response body bytes written, by endpoint.", m.bytesOut)
	counterByLabel("sealsvc_signatures_total", "key", "Files signed, by API key name.", m.signed)
	counterByLabel("sealsvc_rate_limited_total", "key", "Requests refused by the rate limit, by API key name.", m.limited)

	family("sealsvc_auth_failures_total", "counter", "Requests without a valid API key.")
	fmt.Fprintf(w, "sealsvc_auth_failures_total %d\n", m.authFail)
	family("sealsvc_busy_total", "counter", "Requests refused because the concurrency limit was reached.")
	fmt.Fprintf(w, "sealsvc_busy_total %d\n", m.busy)
	family("sealsvc_in_flight_requests", "gauge", "Sign and verify requests being processed.")
	fmt.Fprintf(w, "sealsvc_in_flight_requests %d\n", m.inFlight)
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for s := range m {
		k = append(k, s)
	}
	slices.Sort(k)
	return k
}

// quote quotes a label value as the exposition format requires.
func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}
