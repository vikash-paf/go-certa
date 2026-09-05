package main_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	main "go-certa/cmd/certa-server"
	ocspProt "go-certa/pkg/protocols/ocsp"
	"go-certa/pkg/storage"
	cryptoOCSP "golang.org/x/crypto/ocsp"
)

func TestFullServer_Integration(t *testing.T) {
	var auditBuf bytes.Buffer

	// 1. Initialize ServerApp
	app, err := main.NewServerApp(main.AppConfig{
		ListenAddr:              ":0",
		BaseURL:                 "http://localhost:8080",
		AuditWriter:             &auditBuf,
		SkipChallengeValidation: true,
		CRLInterval:             10 * time.Minute,
		CRLValidity:             24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed creating ServerApp: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := app.Start(ctx); err != nil {
		t.Fatalf("failed starting ServerApp: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		_ = app.Stop(stopCtx)
	}()

	ts := httptest.NewServer(app.Mux)
	defer ts.Close()

	// 2. Test Prometheus /metrics
	t.Run("Prometheus /metrics", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/metrics")
		if err != nil {
			t.Fatalf("GET /metrics failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP 200 on /metrics, got %d", resp.StatusCode)
		}
		contentType := resp.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "text/plain") {
			t.Errorf("unexpected content type: %s", contentType)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "certa_certificates_issued_total") {
			t.Errorf("expected certa_certificates_issued_total in /metrics")
		}
	})

	// 3. Test RFC 5280 CRL Distribution Point: GET /crl/intermediate.crl
	t.Run("CRL /crl/intermediate.crl", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/crl/intermediate.crl")
		if err != nil {
			t.Fatalf("GET /crl/intermediate.crl failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP 200 on /crl/intermediate.crl, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/pkix-crl" {
			t.Errorf("expected application/pkix-crl, got %s", ct)
		}
		crlDER, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed reading CRL body: %v", err)
		}
		crlObj, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			t.Fatalf("failed parsing X.509 CRL DER: %v", err)
		}
		if crlObj.Issuer.CommonName != app.Authority.IntermediateCert.Subject.CommonName {
			t.Errorf("expected CRL issuer %q, got %q", app.Authority.IntermediateCert.Subject.CommonName, crlObj.Issuer.CommonName)
		}
	})

	// 4. Test RFC 5280 AIA caIssuers: GET /ca/intermediate.crt
	t.Run("AIA /ca/intermediate.crt", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/ca/intermediate.crt")
		if err != nil {
			t.Fatalf("GET /ca/intermediate.crt failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP 200, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/pkix-cert" {
			t.Errorf("expected application/pkix-cert, got %s", ct)
		}
		certDER, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed reading intermediate cert: %v", err)
		}
		parsedCert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("failed parsing intermediate cert: %v", err)
		}
		if parsedCert.Subject.CommonName != app.Authority.IntermediateCert.Subject.CommonName {
			t.Errorf("expected intermediate CN %q, got %q", app.Authority.IntermediateCert.Subject.CommonName, parsedCert.Subject.CommonName)
		}
	})

	// 5. Test RFC 8555 ACME Directory: GET /.well-known/acme/directory
	t.Run("ACME Directory", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/.well-known/acme/directory")
		if err != nil {
			t.Fatalf("GET ACME directory failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP 200, got %d", resp.StatusCode)
		}
		var dir map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
			t.Fatalf("failed decoding directory JSON: %v", err)
		}
		if _, ok := dir["newNonce"]; !ok {
			t.Errorf("missing newNonce in ACME directory")
		}
		if _, ok := dir["newAccount"]; !ok {
			t.Errorf("missing newAccount in ACME directory")
		}
		if _, ok := dir["newOrder"]; !ok {
			t.Errorf("missing newOrder in ACME directory")
		}
	})

	// 6. Test RFC 7030 EST CA Certs: GET /.well-known/est/cacerts
	t.Run("EST cacerts", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/.well-known/est/cacerts")
		if err != nil {
			t.Fatalf("GET /.well-known/est/cacerts failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP 200, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/pkcs7-mime" {
			t.Errorf("expected application/pkcs7-mime, got %s", ct)
		}
		body, _ := io.ReadAll(resp.Body)
		if len(body) == 0 {
			t.Errorf("expected non-empty EST cacerts response")
		}
	})

	// 7. Test RFC 6960 OCSP Responder: POST /ocsp
	t.Run("OCSP POST Unknown Certificate", func(t *testing.T) {
		ocspReqBytes, err := cryptoOCSP.CreateRequest(app.Authority.IntermediateCert, app.Authority.IntermediateCert, nil)
		if err != nil {
			t.Fatalf("failed creating ocsp request: %v", err)
		}

		resp, err := http.Post(ts.URL+"/ocsp", "application/ocsp-request", bytes.NewReader(ocspReqBytes))
		if err != nil {
			t.Fatalf("POST /ocsp failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP 200, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/ocsp-response" {
			t.Errorf("expected application/ocsp-response, got %s", ct)
		}

		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed reading ocsp response: %v", err)
		}
		ocspResp, err := cryptoOCSP.ParseResponse(respBytes, app.Authority.IntermediateCert)
		if err != nil {
			t.Fatalf("failed parsing ocsp response: %v", err)
		}
		if ocspResp.Status != cryptoOCSP.Unknown {
			t.Errorf("expected ocsp status Unknown for non-issued cert, got %v", ocspResp.Status)
		}
	})

	// 8. Test Revocation API: POST /api/v1/revoke
	t.Run("Revocation Management API", func(t *testing.T) {
		testSerial := "0123456789abcdef"
		err := app.Storage.SaveCertificate(context.Background(), &storage.CertificateRecord{
			Serial:    testSerial,
			Subject:   "CN=test-revoke.example.com",
			Issuer:    app.Authority.IntermediateCert.Subject.CommonName,
			NotBefore: time.Now().Add(-1 * time.Hour),
			NotAfter:  time.Now().Add(24 * time.Hour),
			RawDER:    []byte{0x30, 0x03, 0x02, 0x01, 0x01},
			PEM:       []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"),
		})
		if err != nil {
			t.Fatalf("failed saving test certificate: %v", err)
		}

		reqBody := `{"serial":"0123456789abcdef","reason":1}`
		resp, err := http.Post(ts.URL+"/api/v1/revoke", "application/json", strings.NewReader(reqBody))
		if err != nil {
			t.Fatalf("POST /api/v1/revoke failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP 200, got %d", resp.StatusCode)
		}
		var revokeResp ocspProt.RevokeResponse
		if err := json.NewDecoder(resp.Body).Decode(&revokeResp); err != nil {
			t.Fatalf("failed decoding revoke response: %v", err)
		}
		if revokeResp.Status != "revoked" {
			t.Errorf("expected status 'revoked', got %q", revokeResp.Status)
		}
	})

	// 9. Verify Cryptographic Audit Chain Integrity
	t.Run("Cryptographic Audit Chain Integrity", func(t *testing.T) {
		valid, err := app.Audit.VerifyChain()
		if err != nil || !valid {
			t.Fatalf("audit chain verification failed: %v", err)
		}
		if app.Audit.EventCount() == 0 {
			t.Errorf("expected recorded audit events")
		}
	})

	// 10. Verify Swagger is disabled by default
	t.Run("Swagger_Disabled_By_Default", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/swagger/")
		if err != nil {
			t.Fatalf("GET /swagger/ failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 when swagger is disabled, got %d", resp.StatusCode)
		}
	})
}

func TestServerApp_SwaggerEnabled(t *testing.T) {
	app, err := main.NewServerApp(main.AppConfig{
		ListenAddr:    ":0",
		BaseURL:       "http://localhost:8080",
		EnableSwagger: true,
	})
	if err != nil {
		t.Fatalf("failed creating ServerApp: %v", err)
	}

	ts := httptest.NewServer(app.Mux)
	defer ts.Close()

	// 1. Check /swagger/ UI page
	resp, err := http.Get(ts.URL + "/swagger/")
	if err != nil {
		t.Fatalf("GET /swagger/ failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for /swagger/, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "swagger-ui") {
		t.Errorf("expected swagger-ui in response body")
	}

	// 2. Check /swagger/doc.json OpenAPI spec
	respDoc, err := http.Get(ts.URL + "/swagger/doc.json")
	if err != nil {
		t.Fatalf("GET /swagger/doc.json failed: %v", err)
	}
	defer respDoc.Body.Close()

	if respDoc.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for /swagger/doc.json, got %d", respDoc.StatusCode)
	}
}

