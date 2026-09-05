package telemetry_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go-certa/pkg/telemetry"
)

func TestMetricsRegistry_CountersAndGauges(t *testing.T) {
	reg := telemetry.NewRegistry()

	// Counters
	reg.IncCertificatesIssued("server-tls")
	reg.IncCertificatesIssued("server-tls")
	reg.IncCertificatesIssued("client-auth")

	reg.IncCertificatesRevoked("key-compromise")
	reg.IncOCSPRequests("good")
	reg.IncOCSPRequests("revoked")
	reg.IncPolicyRejections("weak_key")

	// Gauges
	reg.SetSigningQueueDepth(5)
	if val := reg.GetGauge(telemetry.MetricSigningQueueDepth); val != 5 {
		t.Errorf("expected signing queue depth 5, got %v", val)
	}

	if val := reg.GetCounter(telemetry.MetricCertsIssuedTotal, map[string]string{"profile": "server-tls"}); val != 2 {
		t.Errorf("expected 2 server-tls certs, got %v", val)
	}
	if val := reg.GetCounter(telemetry.MetricCertsIssuedTotal, map[string]string{"profile": "client-auth"}); val != 1 {
		t.Errorf("expected 1 client-auth cert, got %v", val)
	}
	if val := reg.GetGauge(telemetry.MetricRevokedCertsCount); val != 1 {
		t.Errorf("expected 1 revoked cert gauge, got %v", val)
	}

	reg.DecRevokedCertificatesCount()
	if val := reg.GetGauge(telemetry.MetricRevokedCertsCount); val != 0 {
		t.Errorf("expected 0 revoked cert gauge after decrement, got %v", val)
	}
}

func TestMetricsRegistry_PrometheusOutput(t *testing.T) {
	reg := telemetry.NewRegistry()
	reg.IncCertificatesIssued("server-tls")
	reg.SetSigningQueueDepth(3)

	var buf bytes.Buffer
	reg.WritePrometheus(&buf)
	output := buf.String()

	if !strings.Contains(output, "# HELP certa_certificates_issued_total") {
		t.Errorf("missing help string for certs issued")
	}
	if !strings.Contains(output, "# TYPE certa_certificates_issued_total counter") {
		t.Errorf("missing type string for certs issued")
	}
	if !strings.Contains(output, `certa_certificates_issued_total{profile="server-tls"} 1`) {
		t.Errorf("missing formatted counter entry in output:\n%s", output)
	}
	if !strings.Contains(output, "# TYPE certa_signing_queue_depth gauge") {
		t.Errorf("missing type string for queue depth gauge")
	}
	if !strings.Contains(output, "certa_signing_queue_depth 3") {
		t.Errorf("missing formatted gauge entry in output:\n%s", output)
	}
}

func TestMetricsRegistry_HTTPHandler(t *testing.T) {
	reg := telemetry.NewRegistry()
	reg.IncCertificatesIssued("code-signing")

	handler := reg.Handler()

	// 1. GET /metrics
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", rec.Code)
	}
	contentType := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/plain") {
		t.Errorf("unexpected content type: %s", contentType)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `certa_certificates_issued_total{profile="code-signing"} 1`) {
		t.Errorf("expected code-signing metric in body:\n%s", body)
	}

	// 2. HEAD /metrics
	reqHead := httptest.NewRequest(http.MethodHead, "/metrics", nil)
	recHead := httptest.NewRecorder()
	handler.ServeHTTP(recHead, reqHead)

	if recHead.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 on HEAD, got %d", recHead.Code)
	}
	if recHead.Body.Len() != 0 {
		t.Errorf("expected empty body on HEAD")
	}

	// 3. POST /metrics (Method Not Allowed)
	reqPost := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	recPost := httptest.NewRecorder()
	handler.ServeHTTP(recPost, reqPost)

	if recPost.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected HTTP 405 on POST, got %d", recPost.Code)
	}
}

func TestMetricsRegistry_ConcurrentUpdates(t *testing.T) {
	reg := telemetry.NewRegistry()

	var wg sync.WaitGroup
	workers := 25
	iterations := 100

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				reg.IncCertificatesIssued("server-tls")
				reg.IncOCSPRequests("good")
				reg.SetSigningQueueDepth(float64(workerID))
			}
		}(w)
	}

	wg.Wait()

	expectedTotal := float64(workers * iterations)
	if val := reg.GetCounter(telemetry.MetricCertsIssuedTotal, map[string]string{"profile": "server-tls"}); val != expectedTotal {
		t.Errorf("expected %v total issued, got %v", expectedTotal, val)
	}
}
