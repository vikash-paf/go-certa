package ocsp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"go-certa/pkg/storage"
	"golang.org/x/crypto/ocsp"
)

func createTestIssuer(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Issuing CA",
			Organization: []string{"Go-Certa Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func createDelegatedResponderCert(t *testing.T, issuerCert *x509.Certificate, issuerKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Test Delegated OCSP Responder",
			Organization: []string{"Go-Certa Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func createEndEntityCert(t *testing.T, serial *big.Int, issuerCert *x509.Certificate, issuerKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "client.example.com",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestOCSPResponder_LegacyStore(t *testing.T) {
	issuerCert, issuerKey := createTestIssuer(t)
	clientSerial := big.NewInt(99999)
	clientCert := createEndEntityCert(t, clientSerial, issuerCert, issuerKey)

	reqDER, err := ocsp.CreateRequest(clientCert, issuerCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	store := NewMemoryRevocationStore()
	handler := NewHandler(issuerCert, issuerKey, store)

	// Test case: status is Good
	req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	respBody := w.Body.Bytes()
	ocspResp, err := ocsp.ParseResponse(respBody, issuerCert)
	if err != nil {
		t.Fatalf("failed parsing response: %v", err)
	}

	if ocspResp.Status != ocsp.Good {
		t.Errorf("expected Good, got %v", ocspResp.Status)
	}

	// Test case: status is Revoked
	reasonCode := 1
	store.Revoke(clientSerial.String(), reasonCode)

	req = httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	respBody = w.Body.Bytes()
	ocspResp, err = ocsp.ParseResponse(respBody, issuerCert)
	if err != nil {
		t.Fatalf("failed parsing response: %v", err)
	}

	if ocspResp.Status != ocsp.Revoked {
		t.Errorf("expected Revoked, got %v", ocspResp.Status)
	}
	if ocspResp.RevocationReason != reasonCode {
		t.Errorf("expected reason %v, got %v", reasonCode, ocspResp.RevocationReason)
	}
}

func TestDelegatedOCSPResponder(t *testing.T) {
	issuerCert, issuerKey := createTestIssuer(t)
	delegatedCert, delegatedKey := createDelegatedResponderCert(t, issuerCert, issuerKey)

	clientSerial := big.NewInt(54321)
	clientCert := createEndEntityCert(t, clientSerial, issuerCert, issuerKey)

	reqDER, err := ocsp.CreateRequest(clientCert, issuerCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	store := storage.NewMemoryStorage()
	_ = store.SaveCertificate(context.Background(), &storage.CertificateRecord{
		Serial:  storage.NormalizeSerial(clientSerial.Text(16)),
		Subject: "CN=client.example.com",
	})

	handler, err := NewResponder(Config{
		IssuerCert:    issuerCert,
		ResponderCert: delegatedCert,
		Signer:        delegatedKey,
		Storage:       store,
	})
	if err != nil {
		t.Fatalf("NewResponder failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	respBody := w.Body.Bytes()
	// Verification passes against issuerCert because delegated responder cert is embedded and signed by issuerCert
	ocspResp, err := ocsp.ParseResponse(respBody, issuerCert)
	if err != nil {
		t.Fatalf("failed parsing delegated OCSP response: %v", err)
	}

	if ocspResp.Status != ocsp.Good {
		t.Errorf("expected Good, got %v", ocspResp.Status)
	}
}

func TestOCSP_HTTPGet_RFC5019_And_Caching(t *testing.T) {
	issuerCert, issuerKey := createTestIssuer(t)
	clientSerial := big.NewInt(778899)
	clientCert := createEndEntityCert(t, clientSerial, issuerCert, issuerKey)

	reqDER, err := ocsp.CreateRequest(clientCert, issuerCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	store := storage.NewMemoryStorage()
	_ = store.SaveCertificate(context.Background(), &storage.CertificateRecord{
		Serial:  storage.NormalizeSerial(clientSerial.Text(16)),
		Subject: "CN=client.example.com",
	})

	handler, err := NewResponder(Config{
		IssuerCert:  issuerCert,
		Signer:      issuerKey,
		Storage:     store,
		CacheMaxAge: 1800,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Construct RFC 5019 URL: GET /ocsp/{base64-request}
	b64Req := base64.StdEncoding.EncodeToString(reqDER)
	urlPath := "/ocsp/" + url.PathEscape(b64Req)

	// 1. GET Request
	req := httptest.NewRequest(http.MethodGet, urlPath, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/ocsp-response" {
		t.Errorf("expected Content-Type application/ocsp-response, got %s", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=1800, no-transform, must-revalidate" {
		t.Errorf("expected custom Cache-Control, got %s", cc)
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Errorf("expected non-empty ETag header")
	}

	ocspResp, err := ocsp.ParseResponse(w.Body.Bytes(), issuerCert)
	if err != nil {
		t.Fatalf("failed parsing GET response: %v", err)
	}
	if ocspResp.Status != ocsp.Good {
		t.Errorf("expected Good, got %v", ocspResp.Status)
	}

	// 2. Conditional GET with If-None-Match -> 304 Not Modified
	condReq := httptest.NewRequest(http.MethodGet, urlPath, nil)
	condReq.Header.Set("If-None-Match", etag)
	condW := httptest.NewRecorder()
	handler.ServeHTTP(condW, condReq)

	if condW.Code != http.StatusNotModified {
		t.Fatalf("expected 304 Not Modified, got %d", condW.Code)
	}
	if condW.Body.Len() != 0 {
		t.Errorf("expected empty body for 304, got %d bytes", condW.Body.Len())
	}

	// 3. HEAD Request -> 200 OK, empty body
	headReq := httptest.NewRequest(http.MethodHead, urlPath, nil)
	headW := httptest.NewRecorder()
	handler.ServeHTTP(headW, headReq)

	if headW.Code != http.StatusOK {
		t.Fatalf("expected 200 for HEAD, got %d", headW.Code)
	}
	if headW.Body.Len() != 0 {
		t.Errorf("expected empty body for HEAD, got %d bytes", headW.Body.Len())
	}
}

func TestOCSP_UnknownCert(t *testing.T) {
	issuerCert, issuerKey := createTestIssuer(t)
	unknownSerial := big.NewInt(99999999)
	clientCert := createEndEntityCert(t, unknownSerial, issuerCert, issuerKey)

	reqDER, err := ocsp.CreateRequest(clientCert, issuerCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Empty storage - certificate has never been issued
	store := storage.NewMemoryStorage()
	handler, err := NewResponder(Config{
		IssuerCert: issuerCert,
		Signer:     issuerKey,
		Storage:    store,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	ocspResp, err := ocsp.ParseResponse(w.Body.Bytes(), issuerCert)
	if err != nil {
		t.Fatalf("failed parsing response: %v", err)
	}

	if ocspResp.Status != ocsp.Unknown {
		t.Errorf("expected status Unknown (%d), got %v", ocsp.Unknown, ocspResp.Status)
	}
}

func TestOCSP_MethodNotAllowed(t *testing.T) {
	issuerCert, issuerKey := createTestIssuer(t)
	handler := NewHandler(issuerCert, issuerKey, nil)

	req := httptest.NewRequest(http.MethodPut, "/ocsp", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "GET, HEAD, POST" {
		t.Errorf("expected Allow: GET, HEAD, POST, got %s", allow)
	}
}
