package signer

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
	"time"
)

type mockIssuer struct{}

func (m *mockIssuer) SignCertificate(csrDER []byte, serial *big.Int, validity time.Duration, dnsNames []string) ([]byte, error) {
	if string(csrDER) == "fail" {
		return nil, errors.New("signature failed")
	}
	return append([]byte("cert-"), csrDER...), nil
}

func TestHSMSigner(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	latency := 10 * time.Millisecond
	hsm := NewHSMSigner(key, latency)

	if hsm.Public() == nil {
		t.Error("expected public key, got nil")
	}

	data := []byte("hello world")
	digest := sha256.Sum256(data)

	start := time.Now()
	sig, err := hsm.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)

	if elapsed < latency {
		t.Errorf("expected latency at least %v, got %v", latency, elapsed)
	}

	// Verify signature using the public key
	err = rsa.VerifyPKCS1v15(key.Public().(*rsa.PublicKey), crypto.SHA256, digest[:], sig)
	if err != nil {
		t.Error("signature verification failed:", err)
	}
}

func TestWorkerPool(t *testing.T) {
	issuer := &mockIssuer{}
	pool := NewWorkerPool(issuer, 10, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = pool.Start(ctx)
	}()

	resChan := make(chan SignResponse, 1)
	pool.Submit(SignRequest{
		CSRDER:   []byte("test-csr"),
		Serial:   big.NewInt(100),
		Validity: time.Hour,
		ResChan:  resChan,
	})

	select {
	case res := <-resChan:
		if res.Err != nil {
			t.Fatal("unexpected error:", res.Err)
		}
		if string(res.CertDER) != "cert-test-csr" {
			t.Errorf("expected cert-test-csr, got %s", string(res.CertDER))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for response")
	}
}
