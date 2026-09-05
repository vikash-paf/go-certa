package ocsp

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-certa/pkg/storage"
	"golang.org/x/crypto/ocsp"
)

func TestRevocationAPI_SuccessAndOCSPVerification(t *testing.T) {
	issuerCert, issuerKey := createTestIssuer(t)
	serial := big.NewInt(888123)
	clientCert := createEndEntityCert(t, serial, issuerCert, issuerKey)

	store := storage.NewMemoryStorage()
	hexSerial := storage.NormalizeSerial(serial.Text(16))
	err := store.SaveCertificate(context.Background(), &storage.CertificateRecord{
		Serial:  hexSerial,
		Subject: "CN=victim.example.com",
	})
	if err != nil {
		t.Fatalf("failed saving certificate: %v", err)
	}

	api := NewRevocationAPI(store)
	ocspHandler, err := NewResponder(Config{
		IssuerCert: issuerCert,
		Signer:     issuerKey,
		Storage:    store,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Initial OCSP check: status must be Good
	reqDER, err := ocsp.CreateRequest(clientCert, issuerCert, nil)
	if err != nil {
		t.Fatal(err)
	}
	ocspReq := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
	ocspRec := httptest.NewRecorder()
	ocspHandler.ServeHTTP(ocspRec, ocspReq)

	parsedResp, err := ocsp.ParseResponse(ocspRec.Body.Bytes(), issuerCert)
	if err != nil {
		t.Fatal(err)
	}
	if parsedResp.Status != ocsp.Good {
		t.Fatalf("expected Good before revocation, got %v", parsedResp.Status)
	}

	// 2. Invoke Revocation API: POST /api/v1/revoke
	revokePayload := RevokeRequest{
		Serial: hexSerial,
		Reason: storage.ReasonKeyCompromise, // Reason 1
	}
	payloadBytes, _ := json.Marshal(revokePayload)
	apiReq := httptest.NewRequest(http.MethodPost, "/api/v1/revoke", bytes.NewReader(payloadBytes))
	apiRec := httptest.NewRecorder()
	api.HandleRevoke(apiRec, apiReq)

	if apiRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from Revocation API, got %d: %s", apiRec.Code, apiRec.Body.String())
	}

	var apiResp RevokeResponse
	if err := json.Unmarshal(apiRec.Body.Bytes(), &apiResp); err != nil {
		t.Fatalf("failed unmarshaling API response: %v", err)
	}
	if apiResp.Status != "revoked" || apiResp.Serial != hexSerial || apiResp.Reason != storage.ReasonKeyCompromise {
		t.Fatalf("unexpected API response content: %+v", apiResp)
	}

	// 3. Subsequent OCSP query: status must now be Revoked with matching reason
	ocspReq2 := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(reqDER))
	ocspRec2 := httptest.NewRecorder()
	ocspHandler.ServeHTTP(ocspRec2, ocspReq2)

	parsedResp2, err := ocsp.ParseResponse(ocspRec2.Body.Bytes(), issuerCert)
	if err != nil {
		t.Fatal(err)
	}
	if parsedResp2.Status != ocsp.Revoked {
		t.Fatalf("expected status Revoked, got %v", parsedResp2.Status)
	}
	if parsedResp2.RevocationReason != storage.ReasonKeyCompromise {
		t.Fatalf("expected reason %d, got %d", storage.ReasonKeyCompromise, parsedResp2.RevocationReason)
	}
	if parsedResp2.RevokedAt.IsZero() {
		t.Fatalf("expected non-zero RevokedAt timestamp")
	}
}

func TestRevocationAPI_ValidationErrors(t *testing.T) {
	store := storage.NewMemoryStorage()
	_ = store.SaveCertificate(context.Background(), &storage.CertificateRecord{
		Serial:  "12345",
		Subject: "CN=test.com",
	})
	api := NewRevocationAPI(store)

	// 1. Method Not Allowed (GET)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/revoke", nil)
	rec := httptest.NewRecorder()
	api.HandleRevoke(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rec.Code)
	}

	// 2. Malformed JSON
	req = httptest.NewRequest(http.MethodPost, "/api/v1/revoke", bytes.NewReader([]byte("{invalid-json")))
	rec = httptest.NewRecorder()
	api.HandleRevoke(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", rec.Code)
	}

	// 3. Missing serial
	req = httptest.NewRequest(http.MethodPost, "/api/v1/revoke", bytes.NewReader([]byte(`{"serial": ""}`)))
	rec = httptest.NewRecorder()
	api.HandleRevoke(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing serial, got %d", rec.Code)
	}

	// 4. Certificate not found (404)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/revoke", bytes.NewReader([]byte(`{"serial": "nonexistent"}`)))
	rec = httptest.NewRecorder()
	api.HandleRevoke(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing cert, got %d", rec.Code)
	}

	// 5. Successful first revocation then duplicate revocation conflict (409)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/revoke", bytes.NewReader([]byte(`{"serial": "12345", "reason": 1}`)))
	rec = httptest.NewRecorder()
	api.HandleRevoke(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for first revocation, got %d", rec.Code)
	}

	// Duplicate revocation
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/revoke", bytes.NewReader([]byte(`{"serial": "12345", "reason": 1}`)))
	rec2 := httptest.NewRecorder()
	api.HandleRevoke(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for duplicate revocation, got %d", rec2.Code)
	}
}
