package ca_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"go-certa/pkg/ca"
	"go-certa/pkg/signer"
)

func setupTestAuthority(t *testing.T) *ca.Authority {
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
	return auth
}

func generateCSR(t *testing.T, key *rsa.PrivateKey, cn string, dnsNames []string, ips []net.IP) []byte {
	t.Helper()
	csrTmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn, Organization: []string{"Acme Corp"}},
		DNSNames:    dnsNames,
		IPAddresses: ips,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		t.Fatalf("failed creating CSR: %v", err)
	}
	return csrDER
}

func TestGetProfile(t *testing.T) {
	profiles := []ca.ProfileType{
		ca.ProfileServerTLS,
		ca.ProfileClientAuth,
		ca.ProfileCodeSigning,
		ca.ProfileSubCA,
	}

	for _, pt := range profiles {
		p, err := ca.GetProfile(pt)
		if err != nil {
			t.Fatalf("GetProfile(%q) failed: %v", pt, err)
		}
		if p.ProfileType != pt {
			t.Errorf("expected ProfileType %q, got %q", pt, p.ProfileType)
		}
	}

	// Unknown profile
	if _, err := ca.GetProfile("non-existent"); !errors.Is(err, ca.ErrUnknownProfile) {
		t.Fatalf("expected ErrUnknownProfile, got %v", err)
	}
}

func TestProfile_ServerTLS_WithAIA_And_CDP(t *testing.T) {
	auth := setupTestAuthority(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	csrDER := generateCSR(t, key, "api.example.com", []string{"api.example.com"}, []net.IP{net.ParseIP("192.0.2.1")})

	serial := big.NewInt(99001)
	extConfig := ca.ExtensionConfig{
		OCSPServerURLs:         []string{"http://ocsp.example.com"},
		IssuingCertificateURLs: []string{"http://ca.example.com/intermediate.crt"},
		CRLDistributionPoints:  []string{"http://crl.example.com/intermediate.crl"},
	}

	profile := ca.DefaultServerTLSProfile()
	certDER, err := auth.SignCertificateWithProfile(
		csrDER,
		serial,
		profile,
		extConfig,
		30*24*time.Hour,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("SignCertificateWithProfile failed: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	// Verify KeyUsage and ExtKeyUsage
	if cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) == 0 {
		t.Errorf("KeyUsage missing expected flags: %v", cert.KeyUsage)
	}
	foundServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			foundServerAuth = true
		}
	}
	if !foundServerAuth {
		t.Errorf("ExtKeyUsage missing ServerAuth: %v", cert.ExtKeyUsage)
	}

	// Verify IsCA
	if cert.IsCA {
		t.Errorf("expected IsCA=false for ServerTLS profile")
	}

	// Verify SKID & AKID
	expectedSKID, err := ca.ComputeSubjectKeyID(&key.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSubjectKeyID failed: %v", err)
	}
	if !bytes.Equal(cert.SubjectKeyId, expectedSKID) {
		t.Errorf("SKID mismatch: got %x, want %x", cert.SubjectKeyId, expectedSKID)
	}
	if !bytes.Equal(cert.AuthorityKeyId, auth.IntermediateCert.SubjectKeyId) {
		t.Errorf("AKID mismatch: got %x, want %x", cert.AuthorityKeyId, auth.IntermediateCert.SubjectKeyId)
	}

	// Verify AIA & CDP
	if len(cert.OCSPServer) != 1 || cert.OCSPServer[0] != "http://ocsp.example.com" {
		t.Errorf("OCSPServer mismatch: %v", cert.OCSPServer)
	}
	if len(cert.IssuingCertificateURL) != 1 || cert.IssuingCertificateURL[0] != "http://ca.example.com/intermediate.crt" {
		t.Errorf("IssuingCertificateURL mismatch: %v", cert.IssuingCertificateURL)
	}
	if len(cert.CRLDistributionPoints) != 1 || cert.CRLDistributionPoints[0] != "http://crl.example.com/intermediate.crl" {
		t.Errorf("CRLDistributionPoints mismatch: %v", cert.CRLDistributionPoints)
	}

	// Verify SANs
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "api.example.com" {
		t.Errorf("DNSNames mismatch: %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "192.0.2.1" {
		t.Errorf("IPAddresses mismatch: %v", cert.IPAddresses)
	}
}

func TestProfile_ClientAuth(t *testing.T) {
	auth := setupTestAuthority(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER := generateCSR(t, key, "client-app-01", nil, nil)

	profile := ca.DefaultClientAuthProfile()
	certDER, err := auth.SignCertificateWithProfile(
		csrDER,
		big.NewInt(99002),
		profile,
		ca.ExtensionConfig{},
		0, // Should use DefaultValidity
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("SignCertificateWithProfile failed: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	if cert.IsCA {
		t.Errorf("expected IsCA=false")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("expected ExtKeyUsage [ClientAuth], got %v", cert.ExtKeyUsage)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Errorf("expected KeyUsageDigitalSignature")
	}
}

func TestProfile_CodeSigning(t *testing.T) {
	auth := setupTestAuthority(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER := generateCSR(t, key, "Acme Software Release Signing", nil, nil)

	profile := ca.DefaultCodeSigningProfile()
	certDER, err := auth.SignCertificateWithProfile(
		csrDER,
		big.NewInt(99003),
		profile,
		ca.ExtensionConfig{},
		365*24*time.Hour,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("SignCertificateWithProfile failed: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	if cert.IsCA {
		t.Errorf("expected IsCA=false")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Errorf("expected ExtKeyUsage [CodeSigning], got %v", cert.ExtKeyUsage)
	}
}

func TestProfile_SubCA(t *testing.T) {
	auth := setupTestAuthority(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER := generateCSR(t, key, "Go-Certa Downstream Subordinate CA", nil, nil)

	profile := ca.DefaultSubCAProfile()
	certDER, err := auth.SignCertificateWithProfile(
		csrDER,
		big.NewInt(99004),
		profile,
		ca.ExtensionConfig{},
		5*365*24*time.Hour,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("SignCertificateWithProfile failed: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	if !cert.IsCA {
		t.Errorf("expected IsCA=true for SubCA profile")
	}
	expectedKU := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage&expectedKU != expectedKU {
		t.Errorf("expected KeyUsageCertSign | KeyUsageCRLSign, got %v", cert.KeyUsage)
	}
	if !cert.MaxPathLenZero {
		t.Errorf("expected MaxPathLenZero=true for subordinate CA")
	}
}

func TestProfile_ValidationErrors(t *testing.T) {
	auth := setupTestAuthority(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Missing SAN when RequireSAN is true
	csrNoSAN := generateCSR(t, key, "nosan.example.com", nil, nil)
	profile := ca.DefaultServerTLSProfile()

	_, err = auth.SignCertificateWithProfile(
		csrNoSAN,
		big.NewInt(1001),
		profile,
		ca.ExtensionConfig{},
		30*24*time.Hour,
		nil,
		nil,
	)
	if !errors.Is(err, ca.ErrSANRequired) {
		t.Fatalf("expected ErrSANRequired, got %v", err)
	}

	// 2. Exceeding AllowedMaxValidity
	csrWithSAN := generateCSR(t, key, "valid.example.com", []string{"valid.example.com"}, nil)
	excessiveValidity := 400 * 24 * time.Hour // AllowedMaxValidity is 398 days
	_, err = auth.SignCertificateWithProfile(
		csrWithSAN,
		big.NewInt(1002),
		profile,
		ca.ExtensionConfig{},
		excessiveValidity,
		nil,
		nil,
	)
	if !errors.Is(err, ca.ErrValidityExceeded) {
		t.Fatalf("expected ErrValidityExceeded, got %v", err)
	}

	// 3. Nil or non-positive serial
	_, err = auth.SignCertificateWithProfile(csrWithSAN, nil, profile, ca.ExtensionConfig{}, 0, nil, nil)
	if err == nil {
		t.Fatalf("expected error for nil serial")
	}
	_, err = auth.SignCertificateWithProfile(csrWithSAN, big.NewInt(0), profile, ca.ExtensionConfig{}, 0, nil, nil)
	if err == nil {
		t.Fatalf("expected error for zero serial")
	}
	_, err = auth.SignCertificateWithProfile(csrWithSAN, big.NewInt(-1), profile, ca.ExtensionConfig{}, 0, nil, nil)
	if err == nil {
		t.Fatalf("expected error for negative serial")
	}

	// 4. Malformed CSR
	_, err = auth.SignCertificateWithProfile([]byte{0xDE, 0xAD}, big.NewInt(1003), profile, ca.ExtensionConfig{}, 0, nil, nil)
	if err == nil {
		t.Fatalf("expected error for malformed CSR")
	}

	// 5. Proof-of-possession signature verification failure (tampered CSR)
	tamperedCSR := make([]byte, len(csrWithSAN))
	copy(tamperedCSR, csrWithSAN)
	// Mutate bytes near the middle of CSR payload
	tamperedCSR[len(tamperedCSR)/2] ^= 0xFF
	_, err = auth.SignCertificateWithProfile(tamperedCSR, big.NewInt(1004), profile, ca.ExtensionConfig{}, 0, nil, nil)
	if err == nil {
		t.Fatalf("expected proof-of-possession signature failure")
	}
}
