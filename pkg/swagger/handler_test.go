package swagger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSwaggerHandler(t *testing.T) {
	h := NewHandler()

	// 1. Test /swagger/doc.json
	req := httptest.NewRequest(http.MethodGet, "/swagger/doc.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("expected json content-type, got %s", contentType)
	}

	// Verify it parses as valid JSON
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("doc.json is not valid JSON: %v", err)
	}

	// Check title and paths
	info, ok := doc["info"].(map[string]any)
	if !ok || info["title"] != "go-certa PKI & Certificate Authority API" {
		t.Errorf("unexpected info.title: %v", info)
	}

	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatalf("missing paths object in OpenAPI spec")
	}

	expectedPaths := []string{
		"/ca/intermediate.crt",
		"/.well-known/est/cacerts",
		"/.well-known/est/simpleenroll",
		"/.well-known/acme/directory",
		"/acme/new-nonce",
		"/api/v1/revoke",
		"/ocsp",
		"/ocsp/{request}",
		"/crl/intermediate.crl",
		"/metrics",
	}

	for _, p := range expectedPaths {
		if _, exists := paths[p]; !exists {
			t.Errorf("missing expected path %s in OpenAPI spec", p)
		}
	}

	// 2. Test /swagger/ UI page
	req = httptest.NewRequest(http.MethodGet, "/swagger/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	html := rec.Body.String()
	if !strings.Contains(html, "swagger-ui") {
		t.Errorf("expected swagger-ui in HTML body")
	}
	if !strings.Contains(html, "/swagger/doc.json") {
		t.Errorf("expected reference to /swagger/doc.json in HTML body")
	}
}
