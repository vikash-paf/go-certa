package telemetry

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Metric names
const (
	MetricCertsIssuedTotal       = "certa_certificates_issued_total"
	MetricCertsRevokedTotal      = "certa_certificates_revoked_total"
	MetricOCSPRequestsTotal      = "certa_ocsp_requests_total"
	MetricPolicyRejectionsTotal  = "certa_policy_rejections_total"
	MetricSigningQueueDepth      = "certa_signing_queue_depth"
	MetricRevokedCertsCount      = "certa_revoked_certificates_count"
)

type metricType string

const (
	typeCounter metricType = "counter"
	typeGauge   metricType = "gauge"
)

type counterEntry struct {
	labels map[string]string
	value  float64
}

type counterMetric struct {
	name    string
	help    string
	entries map[string]*counterEntry // key = sorted label string
}

type gaugeMetric struct {
	name  string
	help  string
	value float64
}

// Registry manages thread-safe Prometheus metrics without external dependencies.
type Registry struct {
	mu       sync.RWMutex
	counters map[string]*counterMetric
	gauges   map[string]*gaugeMetric
}

// NewRegistry initializes a Registry with standard PKI operational metrics.
func NewRegistry() *Registry {
	r := &Registry{
		counters: make(map[string]*counterMetric),
		gauges:   make(map[string]*gaugeMetric),
	}

	// Register default counters
	r.registerCounter(MetricCertsIssuedTotal, "Total number of certificates issued by profile")
	r.registerCounter(MetricCertsRevokedTotal, "Total number of certificates revoked by reason")
	r.registerCounter(MetricOCSPRequestsTotal, "Total number of OCSP requests processed by status")
	r.registerCounter(MetricPolicyRejectionsTotal, "Total number of certificate requests rejected by policy")

	// Register default gauges
	r.registerGauge(MetricSigningQueueDepth, "Current number of signing requests queued")
	r.registerGauge(MetricRevokedCertsCount, "Total number of currently revoked certificates")

	return r
}

func (r *Registry) registerCounter(name, help string) {
	r.counters[name] = &counterMetric{
		name:    name,
		help:    help,
		entries: make(map[string]*counterEntry),
	}
}

func (r *Registry) registerGauge(name, help string) {
	r.gauges[name] = &gaugeMetric{
		name:  name,
		help:  help,
		value: 0,
	}
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf("%s=%q", k, labels[k]))
	}
	sb.WriteString("}")
	return sb.String()
}

// IncCertificatesIssued increments the issuance counter for a given profile.
func (r *Registry) IncCertificatesIssued(profile string) {
	r.AddCounter(MetricCertsIssuedTotal, 1, map[string]string{"profile": profile})
}

// IncCertificatesRevoked increments the revocation counter for a given reason.
func (r *Registry) IncCertificatesRevoked(reason string) {
	r.AddCounter(MetricCertsRevokedTotal, 1, map[string]string{"reason": reason})
	r.IncRevokedCertificatesCount()
}

// IncOCSPRequests increments the OCSP request counter for a given status (good, revoked, unknown).
func (r *Registry) IncOCSPRequests(status string) {
	r.AddCounter(MetricOCSPRequestsTotal, 1, map[string]string{"status": status})
}

// IncPolicyRejections increments the policy rejection counter for a given reason.
func (r *Registry) IncPolicyRejections(reason string) {
	r.AddCounter(MetricPolicyRejectionsTotal, 1, map[string]string{"reason": reason})
}

// SetSigningQueueDepth updates the signing queue depth gauge.
func (r *Registry) SetSigningQueueDepth(depth float64) {
	r.SetGauge(MetricSigningQueueDepth, depth)
}

// SetRevokedCertificatesCount sets the total revoked certificates count gauge.
func (r *Registry) SetRevokedCertificatesCount(count float64) {
	r.SetGauge(MetricRevokedCertsCount, count)
}

// IncRevokedCertificatesCount increments the revoked certificates gauge by 1.
func (r *Registry) IncRevokedCertificatesCount() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.gauges[MetricRevokedCertsCount]; ok {
		g.value++
	}
}

// DecRevokedCertificatesCount decrements the revoked certificates gauge by 1.
func (r *Registry) DecRevokedCertificatesCount() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.gauges[MetricRevokedCertsCount]; ok && g.value > 0 {
		g.value--
	}
}

// AddCounter adds a delta to the specified counter with given labels.
func (r *Registry) AddCounter(name string, delta float64, labels map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	c, ok := r.counters[name]
	if !ok {
		c = &counterMetric{
			name:    name,
			help:    name,
			entries: make(map[string]*counterEntry),
		}
		r.counters[name] = c
	}

	labelStr := formatLabels(labels)
	entry, exists := c.entries[labelStr]
	if !exists {
		// Clone labels
		lblCopy := make(map[string]string, len(labels))
		for k, v := range labels {
			lblCopy[k] = v
		}
		entry = &counterEntry{labels: lblCopy, value: 0}
		c.entries[labelStr] = entry
	}
	entry.value += delta
}

// SetGauge sets the value of a gauge metric.
func (r *Registry) SetGauge(name string, value float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	g, ok := r.gauges[name]
	if !ok {
		g = &gaugeMetric{name: name, help: name}
		r.gauges[name] = g
	}
	g.value = value
}

// GetCounter retrieves the value of a counter for specific labels.
func (r *Registry) GetCounter(name string, labels map[string]string) float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	c, ok := r.counters[name]
	if !ok {
		return 0
	}
	labelStr := formatLabels(labels)
	entry, exists := c.entries[labelStr]
	if !exists {
		return 0
	}
	return entry.value
}

// GetGauge retrieves the value of a gauge metric.
func (r *Registry) GetGauge(name string) float64 {
	r.mu.RLock()
	defer r.mu.RUnlock()

	g, ok := r.gauges[name]
	if !ok {
		return 0
	}
	return g.value
}

// WritePrometheus serializes the registered metrics in Prometheus 0.0.4 text format.
func (r *Registry) WritePrometheus(w io.Writer) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 1. Sort counter names for deterministic output
	counterNames := make([]string, 0, len(r.counters))
	for name := range r.counters {
		counterNames = append(counterNames, name)
	}
	sort.Strings(counterNames)

	for _, name := range counterNames {
		c := r.counters[name]
		fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
		fmt.Fprintf(w, "# TYPE %s %s\n", c.name, typeCounter)

		// Sort entries by label key
		labelKeys := make([]string, 0, len(c.entries))
		for lk := range c.entries {
			labelKeys = append(labelKeys, lk)
		}
		sort.Strings(labelKeys)

		if len(labelKeys) == 0 {
			fmt.Fprintf(w, "%s 0\n", c.name)
		} else {
			for _, lk := range labelKeys {
				entry := c.entries[lk]
				valStr := strconv.FormatFloat(entry.value, 'f', -1, 64)
				fmt.Fprintf(w, "%s%s %s\n", c.name, lk, valStr)
			}
		}
		fmt.Fprintln(w)
	}

	// 2. Sort gauge names for deterministic output
	gaugeNames := make([]string, 0, len(r.gauges))
	for name := range r.gauges {
		gaugeNames = append(gaugeNames, name)
	}
	sort.Strings(gaugeNames)

	for _, name := range gaugeNames {
		g := r.gauges[name]
		fmt.Fprintf(w, "# HELP %s %s\n", g.name, g.help)
		fmt.Fprintf(w, "# TYPE %s %s\n", g.name, typeGauge)
		valStr := strconv.FormatFloat(g.value, 'f', -1, 64)
		fmt.Fprintf(w, "%s %s\n", g.name, valStr)
		fmt.Fprintln(w)
	}
}

// Handler returns an http.Handler that serves Prometheus metrics on GET /metrics.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if req.Method == http.MethodHead {
			return
		}

		r.WritePrometheus(w)
	})
}
