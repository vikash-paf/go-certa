package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"go-certa/pkg/signer"
)

func TestAuthority(t *testing.T) {
	// 1. Setup mock HSM signer for Intermediate
	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hsmSigner := signer.NewHSMSigner(intKey, 0)

	// 2. Initialize Authority
	auth, err := NewAuthority(hsmSigner)
	if err != nil {
		t.Fatal(err)
	}

	if auth.RootCert.Subject.CommonName != "Go-Certa Root CA G1" {
		t.Errorf("expected Root CA G1, got %s", auth.RootCert.Subject.CommonName)
	}
	if auth.IntermediateCert.Subject.CommonName != "Go-Certa Issuing Intermediate CA 1" {
		t.Errorf("expected Issuing Intermediate CA 1, got %s", auth.IntermediateCert.Subject.CommonName)
	}

	// Verify Intermediate is signed by Root
	roots := x509.NewCertPool()
	roots.AddCert(auth.RootCert)
	_, err = auth.IntermediateCert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		t.Fatalf("Intermediate cert validation failed: %v", err)
	}

	// 3. Create a CSR (Proof-of-Possession)
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "client.example.com",
		},
		DNSNames: []string{"client.example.com"},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, clientKey)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Sign CSR
	serial := big.NewInt(12345)
	validity := 24 * time.Hour
	certDER, err := auth.SignCertificate(csrDER, serial, validity, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Parse and verify signed certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	if cert.SerialNumber.Cmp(serial) != 0 {
		t.Errorf("expected serial %v, got %v", serial, cert.SerialNumber)
	}

	if len(cert.SubjectKeyId) == 0 {
		t.Errorf("expected non-empty SubjectKeyId on issued certificate")
	}
	if len(cert.AuthorityKeyId) == 0 {
		t.Errorf("expected non-empty AuthorityKeyId on issued certificate")
	}

	// Verify cert chain: client -> Intermediate -> Root
	intermediates := x509.NewCertPool()
	intermediates.AddCert(auth.IntermediateCert)

	_, err = cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("Client cert verification failed: %v", err)
	}
}
