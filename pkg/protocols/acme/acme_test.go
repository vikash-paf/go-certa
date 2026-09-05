package acme_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go-certa/pkg/ca"
	"go-certa/pkg/protocols/acme"
	"go-certa/pkg/signer"
	"go-certa/pkg/storage"
)

func TestNonceManager(t *testing.T) {
	nm := acme.NewNonceManager(5 * time.Minute)

	n1, err := nm.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce failed: %v", err)
	}
	if n1 == "" {
		t.Fatalf("empty nonce")
	}

	// First consumption succeeds
	if !nm.ValidateAndConsumeNonce(n1) {
		t.Fatalf("expected valid nonce on first consumption")
	}

	// Replay consumption fails
	if nm.ValidateAndConsumeNonce(n1) {
		t.Fatalf("expected failure on replay consumption")
	}

	// Unknown nonce fails
	if nm.ValidateAndConsumeNonce("unknown-nonce") {
		t.Fatalf("expected failure on unknown nonce")
	}
}

func TestJWS_RSA_And_ECDSA(t *testing.T) {
	// 1. RSA JWS
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	thumbRSA, err := acme.ComputeJWKThumbprint(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("ComputeJWKThumbprint RSA failed: %v", err)
	}
	if thumbRSA == "" {
		t.Fatalf("empty RSA thumbprint")
	}

	jwkRSA, _ := acme.KeyToJWK(&rsaKey.PublicKey)
	payload := []byte(`{"message": "hello acme rsa"}`)
	header := acme.JWSHeader{
		JWK:   jwkRSA,
		Nonce: "test-nonce-1",
	}

	jwsBytes, err := acme.SignJWS(rsaKey, header, payload)
	if err != nil {
		t.Fatalf("SignJWS RSA failed: %v", err)
	}

	parsed, err := acme.DecodeAndVerifyJWS(jwsBytes, nil)
	if err != nil {
		t.Fatalf("DecodeAndVerifyJWS RSA failed: %v", err)
	}
	if string(parsed.Payload) != string(payload) {
		t.Errorf("payload mismatch: got %s, want %s", string(parsed.Payload), string(payload))
	}

	// 2. ECDSA P-256 JWS
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	thumbEC, err := acme.ComputeJWKThumbprint(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("ComputeJWKThumbprint EC failed: %v", err)
	}
	if thumbEC == "" {
		t.Fatalf("empty EC thumbprint")
	}

	jwkEC, _ := acme.KeyToJWK(&ecKey.PublicKey)
	headerEC := acme.JWSHeader{
		JWK:   jwkEC,
		Nonce: "test-nonce-2",
	}
	jwsECBytes, err := acme.SignJWS(ecKey, headerEC, payload)
	if err != nil {
		t.Fatalf("SignJWS EC failed: %v", err)
	}

	parsedEC, err := acme.DecodeAndVerifyJWS(jwsECBytes, nil)
	if err != nil {
		t.Fatalf("DecodeAndVerifyJWS EC failed: %v", err)
	}
	if string(parsedEC.Payload) != string(payload) {
		t.Errorf("payload mismatch: got %s, want %s", string(parsedEC.Payload), string(payload))
	}
}

func setupTestACMEServer(t *testing.T) (*httptest.Server, *acme.Server, *ca.Authority) {
	t.Helper()
	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hsm := signer.NewHSMSigner(intKey, 0)
	auth, err := ca.NewAuthority(hsm)
	if err != nil {
		t.Fatal(err)
	}

	store := storage.NewMemoryStorage()

	// Initial server config with placeholder BaseURL
	server, err := acme.NewServer(acme.ServerConfig{
		BaseURL:                 "http://placeholder",
		Authority:               auth,
		Storage:                 store,
		SkipChallengeValidation: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server)

	// Reconfigure BaseURL to test server URL
	serverReconfigured, err := acme.NewServer(acme.ServerConfig{
		BaseURL:                 ts.URL,
		Authority:               auth,
		Storage:                 store,
		SkipChallengeValidation: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = serverReconfigured

	return ts, serverReconfigured, auth
}

func TestACME_EndToEndIssuance(t *testing.T) {
	ts, _, auth := setupTestACMEServer(t)
	defer ts.Close()

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientJWK, err := acme.KeyToJWK(&clientKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Directory lookup
	dirResp, err := http.Get(ts.URL + "/.well-known/acme/directory")
	if err != nil {
		t.Fatalf("GET directory failed: %v", err)
	}
	defer dirResp.Body.Close()
	if dirResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for directory, got %d", dirResp.StatusCode)
	}

	var dir map[string]string
	_ = json.NewDecoder(dirResp.Body).Decode(&dir)
	newNonceURL := dir["newNonce"]
	newAccountURL := dir["newAccount"]
	newOrderURL := dir["newOrder"]

	// 2. Fetch fresh nonce
	nonceResp, err := http.Head(newNonceURL)
	if err != nil {
		t.Fatalf("HEAD newNonce failed: %v", err)
	}
	defer nonceResp.Body.Close()
	nonce := nonceResp.Header.Get("Replay-Nonce")
	if nonce == "" {
		t.Fatalf("expected Replay-Nonce header")
	}

	// 3. Register Account
	accountPayload := []byte(`{"contact":["mailto:admin@example.com"],"termsOfServiceAgreed":true}`)
	acctJWS, err := acme.SignJWS(clientKey, acme.JWSHeader{
		JWK:   clientJWK,
		Nonce: nonce,
		URL:   newAccountURL,
	}, accountPayload)
	if err != nil {
		t.Fatalf("SignJWS for newAccount failed: %v", err)
	}

	acctResp, err := http.Post(newAccountURL, "application/jose+json", bytes.NewReader(acctJWS))
	if err != nil {
		t.Fatalf("POST newAccount failed: %v", err)
	}
	defer acctResp.Body.Close()

	if acctResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(acctResp.Body)
		t.Fatalf("expected 201 Created for newAccount, got %d: %s", acctResp.StatusCode, string(body))
	}
	accountURL := acctResp.Header.Get("Location")
	if accountURL == "" {
		t.Fatalf("expected Location header for newAccount")
	}
	nonce = acctResp.Header.Get("Replay-Nonce")
	if nonce == "" {
		t.Fatalf("expected Replay-Nonce header in newAccount response")
	}

	// 4. Create Order for "test.example.com"
	orderPayload := []byte(`{"identifiers":[{"type":"dns","value":"test.example.com"}]}`)
	orderJWS, err := acme.SignJWS(clientKey, acme.JWSHeader{
		Kid:   accountURL,
		Nonce: nonce,
		URL:   newOrderURL,
	}, orderPayload)
	if err != nil {
		t.Fatalf("SignJWS for newOrder failed: %v", err)
	}

	orderResp, err := http.Post(newOrderURL, "application/jose+json", bytes.NewReader(orderJWS))
	if err != nil {
		t.Fatalf("POST newOrder failed: %v", err)
	}
	defer orderResp.Body.Close()

	if orderResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(orderResp.Body)
		t.Fatalf("expected 201 Created for newOrder, got %d: %s", orderResp.StatusCode, string(body))
	}
	orderURL := orderResp.Header.Get("Location")
	nonce = orderResp.Header.Get("Replay-Nonce")

	var order acme.Order
	_ = json.NewDecoder(orderResp.Body).Decode(&order)
	if len(order.Authorizations) == 0 {
		t.Fatalf("expected authorizations in newOrder response")
	}
	authzURL := order.Authorizations[0]
	finalizeURL := order.FinalizeURL

	// 5. Fetch Authorization & Challenge
	authzResp, err := http.Get(authzURL)
	if err != nil {
		t.Fatalf("GET authz failed: %v", err)
	}
	defer authzResp.Body.Close()
	var authz acme.Authorization
	_ = json.NewDecoder(authzResp.Body).Decode(&authz)

	if len(authz.Challenges) == 0 {
		t.Fatalf("expected at least one challenge in authz")
	}
	chalURL := authz.Challenges[0].URL

	// 6. Trigger Challenge Verification
	chalJWS, err := acme.SignJWS(clientKey, acme.JWSHeader{
		Kid:   accountURL,
		Nonce: nonce,
		URL:   chalURL,
	}, []byte(`{}`))
	if err != nil {
		t.Fatalf("SignJWS for challenge failed: %v", err)
	}

	chalResp, err := http.Post(chalURL, "application/jose+json", bytes.NewReader(chalJWS))
	if err != nil {
		t.Fatalf("POST challenge failed: %v", err)
	}
	defer chalResp.Body.Close()
	if chalResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(chalResp.Body)
		t.Fatalf("expected 200 OK for challenge, got %d: %s", chalResp.StatusCode, string(body))
	}
	nonce = chalResp.Header.Get("Replay-Nonce")

	// 7. Verify Order Status is now "ready"
	checkOrderResp, err := http.Get(orderURL)
	if err != nil {
		t.Fatalf("GET order failed: %v", err)
	}
	defer checkOrderResp.Body.Close()
	var updatedOrder acme.Order
	_ = json.NewDecoder(checkOrderResp.Body).Decode(&updatedOrder)
	if updatedOrder.Status != "ready" {
		t.Fatalf("expected order status 'ready', got %q", updatedOrder.Status)
	}

	// 8. Generate CSR and Finalize Order
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, certKey)
	if err != nil {
		t.Fatal(err)
	}

	csrB64 := base64.RawURLEncoding.EncodeToString(csrDER)
	finalizePayload := []byte(`{"csr":"` + csrB64 + `"}`)

	finalizeJWS, err := acme.SignJWS(clientKey, acme.JWSHeader{
		Kid:   accountURL,
		Nonce: nonce,
		URL:   finalizeURL,
	}, finalizePayload)
	if err != nil {
		t.Fatalf("SignJWS for finalize failed: %v", err)
	}

	finResp, err := http.Post(finalizeURL, "application/jose+json", bytes.NewReader(finalizeJWS))
	if err != nil {
		t.Fatalf("POST finalize failed: %v", err)
	}
	defer finResp.Body.Close()

	if finResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(finResp.Body)
		t.Fatalf("expected 200 OK for finalize, got %d: %s", finResp.StatusCode, string(body))
	}

	var finalizedOrder acme.Order
	_ = json.NewDecoder(finResp.Body).Decode(&finalizedOrder)
	if finalizedOrder.Status != "valid" {
		t.Fatalf("expected order status 'valid', got %q", finalizedOrder.Status)
	}
	if finalizedOrder.CertificateURL == "" {
		t.Fatalf("expected certificate URL in finalized order")
	}

	// 9. Download Certificate
	certResp, err := http.Get(finalizedOrder.CertificateURL)
	if err != nil {
		t.Fatalf("GET certificate failed: %v", err)
	}
	defer certResp.Body.Close()

	if certResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for cert download, got %d", certResp.StatusCode)
	}
	if ct := certResp.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
		t.Errorf("expected application/pem-certificate-chain, got %s", ct)
	}

	certPEMBytes, err := io.ReadAll(certResp.Body)
	if err != nil {
		t.Fatal(err)
	}

	block, rest := pem.Decode(certPEMBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("failed decoding leaf certificate PEM")
	}

	leafCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed parsing leaf certificate: %v", err)
	}

	if len(leafCert.DNSNames) != 1 || leafCert.DNSNames[0] != "test.example.com" {
		t.Errorf("expected SAN 'test.example.com', got %v", leafCert.DNSNames)
	}

	// Verify certificate chain against Intermediate and Root
	roots := x509.NewCertPool()
	roots.AddCert(auth.RootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(auth.IntermediateCert)

	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       "test.example.com",
	})
	if err != nil {
		t.Fatalf("certificate verification against trust chain failed: %v", err)
	}

	// Also verify intermediate cert is in PEM rest
	intBlock, _ := pem.Decode(rest)
	if intBlock == nil || intBlock.Type != "CERTIFICATE" {
		t.Fatalf("expected intermediate certificate in chain PEM")
	}
}
