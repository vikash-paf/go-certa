package crl_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-certa/pkg/ca"
	"go-certa/pkg/protocols/crl"
	"go-certa/pkg/signer"
	"go-certa/pkg/storage"
)

func setupTestHierarchy(t *testing.T) (*ca.Authority, storage.Storage) {
	t.Helper()
	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating intermediate key: %v", err)
	}
	hsm := signer.NewHSMSigner(intKey, 0)
	auth, err := ca.NewAuthority(hsm)
	if err != nil {
		t.Fatalf("failed initializing authority: %v", err)
	}
	store := storage.NewMemoryStorage()
	return auth, store
}

func TestGenerateCRL_Empty(t *testing.T) {
	auth, store := setupTestHierarchy(t)
	ctx := context.Background()

	generator, err := crl.NewCRLGenerator(auth.IntermediateCert, auth.Signer, store, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewCRLGenerator failed: %v", err)
	}

	crlDER, err := generator.GenerateCRL(ctx)
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}

	parsedCRL, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList failed: %v", err)
	}

	// Verify signature from Intermediate CA
	if err := parsedCRL.CheckSignatureFrom(auth.IntermediateCert); err != nil {
		t.Fatalf("CRL signature verification failed: %v", err)
	}

	// Verify empty revocation list
	if len(parsedCRL.RevokedCertificateEntries) != 0 {
		t.Fatalf("expected 0 revoked entries, got %d", len(parsedCRL.RevokedCertificateEntries))
	}

	// Verify CRL Number
	if parsedCRL.Number == nil || parsedCRL.Number.Int64() != 1 {
		t.Fatalf("expected CRL number 1, got %v", parsedCRL.Number)
	}

	// Verify dates
	if !parsedCRL.NextUpdate.After(parsedCRL.ThisUpdate) {
		t.Fatalf("NextUpdate %v must be after ThisUpdate %v", parsedCRL.NextUpdate, parsedCRL.ThisUpdate)
	}
}

func TestGenerateCRL_WithRevocations(t *testing.T) {
	auth, store := setupTestHierarchy(t)
	ctx := context.Background()

	// Populate 3 certificates
	c1 := &storage.CertificateRecord{Serial: "0100a1", Subject: "CN=cert1.com"}
	c2 := &storage.CertificateRecord{Serial: "0200b2", Subject: "CN=cert2.com"}
	c3 := &storage.CertificateRecord{Serial: "0300c3", Subject: "CN=cert3.com"}
	_ = store.SaveCertificate(ctx, c1)
	_ = store.SaveCertificate(ctx, c2)
	_ = store.SaveCertificate(ctx, c3)

	// Revoke 2 certificates with different reasons
	t1 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	t2 := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	if err := store.RevokeCertificate(ctx, "0100a1", storage.ReasonKeyCompromise, t1); err != nil {
		t.Fatalf("RevokeCertificate 1 failed: %v", err)
	}
	if err := store.RevokeCertificate(ctx, "0300c3", storage.ReasonCessationOfOperation, t2); err != nil {
		t.Fatalf("RevokeCertificate 2 failed: %v", err)
	}

	generator, err := crl.NewCRLGenerator(auth.IntermediateCert, auth.Signer, store, 48*time.Hour)
	if err != nil {
		t.Fatalf("NewCRLGenerator failed: %v", err)
	}

	crlDER, err := generator.GenerateCRL(ctx)
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}

	parsedCRL, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList failed: %v", err)
	}

	if err := parsedCRL.CheckSignatureFrom(auth.IntermediateCert); err != nil {
		t.Fatalf("signature check failed: %v", err)
	}

	if len(parsedCRL.RevokedCertificateEntries) != 2 {
		t.Fatalf("expected 2 revoked entries, got %d", len(parsedCRL.RevokedCertificateEntries))
	}

	expectedSerials := map[string]int{
		"100a1": storage.ReasonKeyCompromise,
		"300c3": storage.ReasonCessationOfOperation,
	}

	for _, entry := range parsedCRL.RevokedCertificateEntries {
		hexStr := entry.SerialNumber.Text(16)
		expectedReason, found := expectedSerials[hexStr]
		if !found {
			t.Fatalf("unexpected serial in CRL: %s", hexStr)
		}
		if entry.ReasonCode != expectedReason {
			t.Errorf("reason code mismatch for %s: got %d, want %d", hexStr, entry.ReasonCode, expectedReason)
		}
	}
}

func TestCRLNumber_Increment(t *testing.T) {
	auth, store := setupTestHierarchy(t)
	ctx := context.Background()

	generator, err := crl.NewCRLGenerator(auth.IntermediateCert, auth.Signer, store, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	for expectedNum := int64(1); expectedNum <= 3; expectedNum++ {
		der, err := generator.GenerateCRL(ctx)
		if err != nil {
			t.Fatalf("iteration %d GenerateCRL failed: %v", expectedNum, err)
		}
		parsed, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatalf("iteration %d ParseRevocationList failed: %v", expectedNum, err)
		}
		if parsed.Number.Int64() != expectedNum {
			t.Errorf("expected CRL Number %d, got %v", expectedNum, parsed.Number)
		}
	}
}

func TestCRLService_Lifecycle(t *testing.T) {
	auth, store := setupTestHierarchy(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	generator, _ := crl.NewCRLGenerator(auth.IntermediateCert, auth.Signer, store, 24*time.Hour)
	service := crl.NewCRLService(generator, 50*time.Millisecond)

	// Before start, LatestCRL returns ErrCRLNotReady
	if _, _, err := service.LatestCRL(); err != crl.ErrCRLNotReady {
		t.Fatalf("expected ErrCRLNotReady before start, got %v", err)
	}

	// Start service
	if err := service.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// LatestCRL should now succeed
	crlDER, lastGen, err := service.LatestCRL()
	if err != nil {
		t.Fatalf("LatestCRL failed: %v", err)
	}
	if len(crlDER) == 0 {
		t.Fatalf("expected non-empty CRL")
	}
	if lastGen.IsZero() {
		t.Fatalf("expected non-zero lastGen timestamp")
	}

	// Manual regeneration
	newDER, err := service.Regenerate(ctx)
	if err != nil {
		t.Fatalf("Regenerate failed: %v", err)
	}
	if len(newDER) == 0 {
		t.Fatalf("expected non-empty regenerated CRL")
	}

	service.Stop()
}

func TestCRLHandler(t *testing.T) {
	auth, store := setupTestHierarchy(t)
	ctx := context.Background()

	generator, _ := crl.NewCRLGenerator(auth.IntermediateCert, auth.Signer, store, 24*time.Hour)
	service := crl.NewCRLService(generator, time.Hour)
	handler := crl.NewHandler(service, crl.WithCacheMaxAge(7200))

	// 1. CRL Not Ready (503 Service Unavailable)
	req := httptest.NewRequest(http.MethodGet, "/crl/intermediate.crl", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 before generation, got %d", rr.Code)
	}

	// Generate initial CRL
	_, err := service.Regenerate(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 2. HTTP GET - 200 OK
	req = httptest.NewRequest(http.MethodGet, "/crl/intermediate.crl", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/pkix-crl" {
		t.Errorf("expected Content-Type application/pkix-crl, got %s", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "public, max-age=7200, must-revalidate" {
		t.Errorf("expected custom max-age 7200, got %s", cc)
	}
	if lm := rr.Header().Get("Last-Modified"); lm == "" {
		t.Errorf("expected Last-Modified header")
	}

	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseRevocationList(body); err != nil {
		t.Fatalf("failed parsing response body as CRL: %v", err)
	}

	// 3. HTTP HEAD - 200 OK with no body
	headReq := httptest.NewRequest(http.MethodHead, "/crl/intermediate.crl", nil)
	headRR := httptest.NewRecorder()
	handler.ServeHTTP(headRR, headReq)

	if headRR.Code != http.StatusOK {
		t.Fatalf("expected 200 for HEAD, got %d", headRR.Code)
	}
	if headRR.Body.Len() != 0 {
		t.Fatalf("expected empty body for HEAD, got %d bytes", headRR.Body.Len())
	}
	if headRR.Header().Get("Content-Length") == "" {
		t.Fatalf("expected Content-Length header for HEAD")
	}

	// 4. HTTP POST - 405 Method Not Allowed
	postReq := httptest.NewRequest(http.MethodPost, "/crl/intermediate.crl", nil)
	postRR := httptest.NewRecorder()
	handler.ServeHTTP(postRR, postReq)

	if postRR.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", postRR.Code)
	}
	if allow := postRR.Header().Get("Allow"); allow != "GET, HEAD" {
		t.Errorf("expected Allow header 'GET, HEAD', got %s", allow)
	}
}
