package ocsp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestOCSPResponder(t *testing.T) {
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	issuerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Issuer",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}

	clientSerial := big.NewInt(99999)
	clientTmpl := &x509.Certificate{
		SerialNumber: clientSerial,
		Subject: pkix.Name{
			CommonName: "Client",
		},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, issuerCert, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatal(err)
	}

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
