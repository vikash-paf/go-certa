package est

import (
	"bytes"
	"context"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-certa/pkg/signer"
)

type dummyIssuer struct{}

func (d *dummyIssuer) SignCertificate(csrDER []byte, serial *big.Int, validity time.Duration, dnsNames []string) ([]byte, error) {
	return append([]byte("cert-"), csrDER...), nil
}

func TestESTHandler(t *testing.T) {
	issuer := &dummyIssuer{}
	pool := signer.NewWorkerPool(issuer, 10, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = pool.Start(ctx)
	}()

	caCertDER := []byte("ca-cert-bytes")
	handler := NewHandler(pool, caCertDER)

	// Test CACerts endpoint
	req := httptest.NewRequest(http.MethodGet, "/.well-known/est/cacerts", nil)
	w := httptest.NewRecorder()
	handler.HandleCACerts(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/pkcs7-mime" {
		t.Errorf("expected application/pkcs7-mime, got %s", contentType)
	}

	// Test SimpleEnroll endpoint
	csrInput := []byte("client-csr")
	csrBase64 := base64.StdEncoding.EncodeToString(csrInput)

	req = httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", bytes.NewReader([]byte(csrBase64)))
	w = httptest.NewRecorder()
	handler.HandleSimpleEnroll(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	expectedBody := append([]byte("cert-"), csrInput...)
	if !bytes.Equal(w.Body.Bytes(), expectedBody) {
		t.Errorf("expected %s, got %s", expectedBody, w.Body.Bytes())
	}
}
