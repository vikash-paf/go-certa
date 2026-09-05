package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestServerApp_PersistenceAcrossRestarts(t *testing.T) {
	dataDir := t.TempDir()

	// ==========================================
	// Phase 1: Boot First Server Instance
	// ==========================================
	var auditBuf1 bytes.Buffer
	app1, err := NewServerApp(AppConfig{
		ListenAddr:              ":0",
		BaseURL:                 "http://localhost:8080",
		DataDir:                 dataDir,
		AuditWriter:             &auditBuf1,
		SkipChallengeValidation: true,
	})
	if err != nil {
		t.Fatalf("first NewServerApp failed: %v", err)
	}

	serverCtx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	if err := app1.Start(serverCtx1); err != nil {
		t.Fatalf("app1.Start failed: %v", err)
	}

	rootCert1 := app1.Authority.RootCert
	intCert1 := app1.Authority.IntermediateCert

	// Enroll a client via EST /simpleenroll
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "persistence-test.example.com"},
		DNSNames: []string{"persistence-test.example.com"},
	}, clientKey)
	if err != nil {
		t.Fatal(err)
	}

	b64CSR := base64.StdEncoding.EncodeToString(csrDER)
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", bytes.NewBufferString(b64CSR))
	rec := httptest.NewRecorder()
	app1.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("EST enrollment failed on app1: %d %s", rec.Code, rec.Body.String())
	}

	certDER := rec.Body.Bytes()
	clientCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed parsing enrolled cert: %v", err)
	}
	serialHex := fmt.Sprintf("%x", clientCert.SerialNumber)

	// Stop app1 gracefully
	shutdownCtx1, shutdownCancel1 := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel1()
	if err := app1.Stop(shutdownCtx1); err != nil {
		t.Fatalf("app1.Stop failed: %v", err)
	}
	cancel1()

	// ==========================================
	// Phase 2: Boot Second Server Instance
	// ==========================================
	var auditBuf2 bytes.Buffer
	app2, err := NewServerApp(AppConfig{
		ListenAddr:              ":0",
		BaseURL:                 "http://localhost:8080",
		DataDir:                 dataDir,
		AuditWriter:             &auditBuf2,
		SkipChallengeValidation: true,
	})
	if err != nil {
		t.Fatalf("second NewServerApp failed: %v", err)
	}

	serverCtx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if err := app2.Start(serverCtx2); err != nil {
		t.Fatalf("app2.Start failed: %v", err)
	}

	// 1. Verify CA hierarchy is identical
	if app2.Authority.RootCert.SerialNumber.Cmp(rootCert1.SerialNumber) != 0 {
		t.Fatalf("Root CA serial changed across restarts")
	}
	if app2.Authority.IntermediateCert.SerialNumber.Cmp(intCert1.SerialNumber) != 0 {
		t.Fatalf("Intermediate CA serial changed across restarts")
	}
	if string(app2.Authority.IntermediateCert.SubjectKeyId) != string(intCert1.SubjectKeyId) {
		t.Fatalf("Intermediate CA SKID changed across restarts")
	}

	// 2. Query OCSP on app2 for the certificate enrolled by app1
	ocspReqDER, err := ocsp.CreateRequest(clientCert, app2.Authority.IntermediateCert, nil)
	if err != nil {
		t.Fatalf("failed creating ocsp request: %v", err)
	}

	ocspReq := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(ocspReqDER))
	ocspReq.Header.Set("Content-Type", "application/ocsp-request")
	ocspRec := httptest.NewRecorder()
	app2.Mux.ServeHTTP(ocspRec, ocspReq)

	if ocspRec.Code != http.StatusOK {
		t.Fatalf("OCSP query failed on app2: %d", ocspRec.Code)
	}

	ocspResp, err := ocsp.ParseResponse(ocspRec.Body.Bytes(), app2.Authority.IntermediateCert)
	if err != nil {
		t.Fatalf("failed parsing ocsp response: %v", err)
	}
	if ocspResp.Status != ocsp.Good {
		t.Fatalf("expected status Good on app2, got %v", ocspResp.Status)
	}

	// 3. Revoke certificate on app2
	revokePayload, _ := json.Marshal(map[string]any{
		"serial": serialHex,
		"reason": 1,
	})
	revokeReq := httptest.NewRequest(http.MethodPost, "/api/v1/revoke", bytes.NewReader(revokePayload))
	revokeReq.Header.Set("Content-Type", "application/json")
	revokeRec := httptest.NewRecorder()
	app2.Mux.ServeHTTP(revokeRec, revokeReq)

	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revocation failed on app2: %d %s", revokeRec.Code, revokeRec.Body.String())
	}

	// 4. Re-query OCSP on app2: must now be Revoked!
	ocspReq2 := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(ocspReqDER))
	ocspReq2.Header.Set("Content-Type", "application/ocsp-request")
	ocspRec2 := httptest.NewRecorder()
	app2.Mux.ServeHTTP(ocspRec2, ocspReq2)

	ocspResp2, err := ocsp.ParseResponse(ocspRec2.Body.Bytes(), app2.Authority.IntermediateCert)
	if err != nil {
		t.Fatalf("failed parsing ocsp response: %v", err)
	}
	if ocspResp2.Status != ocsp.Revoked {
		t.Fatalf("expected status Revoked on app2, got %v", ocspResp2.Status)
	}
	if ocspResp2.RevocationReason != 1 {
		t.Fatalf("expected revocation reason 1, got %d", ocspResp2.RevocationReason)
	}

	// 5. Verify audit log file was persisted on disk
	auditLogPath := filepath.Join(dataDir, "audit.log")
	auditData, err := io.ReadAll(bytes.NewReader(auditBuf2.Bytes()))
	if err != nil || len(auditData) == 0 {
		t.Fatalf("expected audit log entries to be recorded, path: %s", auditLogPath)
	}

	// Stop app2 gracefully
	shutdownCtx2, shutdownCancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel2()
	if err := app2.Stop(shutdownCtx2); err != nil {
		t.Fatalf("app2.Stop failed: %v", err)
	}
}
