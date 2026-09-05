package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrInitializeAuthority_Persistence(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Initial creation
	auth1, signer1, err := LoadOrInitializeAuthority(tempDir, 0)
	if err != nil {
		t.Fatalf("first LoadOrInitializeAuthority failed: %v", err)
	}

	rootCN1 := auth1.RootCert.Subject.CommonName
	intCN1 := auth1.IntermediateCert.Subject.CommonName
	rootSKID1 := auth1.RootCert.SubjectKeyId
	intSKID1 := auth1.IntermediateCert.SubjectKeyId

	// Verify files exist
	caDir := filepath.Join(tempDir, "ca")
	paths := DefaultCAHierarchyFiles(caDir)
	if !filesExist(paths.RootKeyPath, paths.RootCertPath, paths.IntermediateKeyPath, paths.IntermediateCertPath) {
		t.Fatalf("expected all CA files to exist on disk")
	}

	// 2. Second invocation: must reload exact same keys and certs!
	auth2, signer2, err := LoadOrInitializeAuthority(tempDir, 0)
	if err != nil {
		t.Fatalf("second LoadOrInitializeAuthority failed: %v", err)
	}

	if auth2.RootCert.Subject.CommonName != rootCN1 {
		t.Errorf("expected root CN %s, got %s", rootCN1, auth2.RootCert.Subject.CommonName)
	}
	if auth2.IntermediateCert.Subject.CommonName != intCN1 {
		t.Errorf("expected intermediate CN %s, got %s", intCN1, auth2.IntermediateCert.Subject.CommonName)
	}
	if string(auth2.RootCert.SubjectKeyId) != string(rootSKID1) {
		t.Errorf("root SKID changed across reloads")
	}
	if string(auth2.IntermediateCert.SubjectKeyId) != string(intSKID1) {
		t.Errorf("intermediate SKID changed across reloads")
	}

	// Generate CSR inline
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "reload-test.example.com"},
		DNSNames: []string{"reload-test.example.com"},
	}, clientKey)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := GenerateSerial()
	if err != nil {
		t.Fatalf("GenerateSerial failed: %v", err)
	}

	certDER, err := auth1.SignCertificate(csrDER, serial, 30*24*time.Hour, []string{"reload-test.example.com"})
	if err != nil {
		t.Fatalf("SignCertificate failed: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	// Verify certificate using auth2's intermediate cert
	roots := x509.NewCertPool()
	roots.AddCert(auth2.RootCert)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(auth2.IntermediateCert)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       "reload-test.example.com",
	}

	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("certificate verification failed against reloaded authority: %v", err)
	}

	_ = signer1
	_ = signer2
}
