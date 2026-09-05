package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"go-certa/pkg/ca"
)

func TestPolicy_WeakRSAKeyRejection(t *testing.T) {
	policy := ca.NewDefaultPolicyEngine()

	// 1. Weak 1024-bit RSA key
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	err = policy.ValidatePublicKey(&weakKey.PublicKey)
	if !errors.Is(err, ca.ErrWeakRSAKey) {
		t.Fatalf("expected ErrWeakRSAKey for 1024-bit key, got %v", err)
	}

	// 2. Compliant 2048-bit RSA key
	goodKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.ValidatePublicKey(&goodKey.PublicKey); err != nil {
		t.Fatalf("expected 2048-bit RSA key to pass, got %v", err)
	}
}

func TestPolicy_ECCKeyCurves(t *testing.T) {
	policy := ca.NewDefaultPolicyEngine()

	// 1. Allowed Curves: P-256, P-384, P-521
	allowedCurves := []elliptic.Curve{
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}
	for _, c := range allowedCurves {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.ValidatePublicKey(&k.PublicKey); err != nil {
			t.Fatalf("curve %v failed validation: %v", c.Params().Name, err)
		}
	}

	// 2. Disallowed Curve: P-224
	disallowedKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	err = policy.ValidatePublicKey(&disallowedKey.PublicKey)
	if !errors.Is(err, ca.ErrUnsupportedKey) {
		t.Fatalf("expected ErrUnsupportedKey for P-224 curve, got %v", err)
	}
}

func TestPolicy_WildcardValidation(t *testing.T) {
	policy := ca.NewDefaultPolicyEngine()

	// Valid wildcard (*.domain.com)
	if err := policy.ValidateDNSName("*.domain.com"); err != nil {
		t.Fatalf("expected *.domain.com to pass, got %v", err)
	}

	// Wildcard disabled
	noWildcards := ca.NewDefaultPolicyEngine()
	noWildcards.AllowWildcards = false
	if err := noWildcards.ValidateDNSName("*.domain.com"); !errors.Is(err, ca.ErrInvalidWildcard) {
		t.Fatalf("expected ErrInvalidWildcard when wildcards disabled, got %v", err)
	}

	// Dangerous wildcard directly on TLD (*.com)
	if err := policy.ValidateDNSName("*.com"); !errors.Is(err, ca.ErrInvalidWildcard) {
		t.Fatalf("expected ErrInvalidWildcard for *.com, got %v", err)
	}

	// Single asterisk (*)
	if err := policy.ValidateDNSName("*"); !errors.Is(err, ca.ErrInvalidWildcard) {
		t.Fatalf("expected ErrInvalidWildcard for solitary '*', got %v", err)
	}

	// Non-leftmost wildcard (sub.*.domain.com)
	if err := policy.ValidateDNSName("sub.*.domain.com"); !errors.Is(err, ca.ErrInvalidWildcard) {
		t.Fatalf("expected ErrInvalidWildcard for non-leftmost wildcard, got %v", err)
	}

	// Multiple wildcards (*.*.domain.com)
	if err := policy.ValidateDNSName("*.*.domain.com"); !errors.Is(err, ca.ErrInvalidWildcard) {
		t.Fatalf("expected ErrInvalidWildcard for multiple wildcards, got %v", err)
	}
}

func TestPolicy_DisallowedDNSNames(t *testing.T) {
	policy := ca.NewDefaultPolicyEngine()

	disallowed := []string{
		"localhost",
		"dev.local",
		"service.internal",
		"hidden.onion",
		"host.lan",
		"test.invalid",
	}

	for _, d := range disallowed {
		err := policy.ValidateDNSName(d)
		if !errors.Is(err, ca.ErrForbiddenDNSName) {
			t.Fatalf("expected ErrForbiddenDNSName for %q, got %v", d, err)
		}
	}
}

func TestPolicy_CSRValidation(t *testing.T) {
	policy := ca.NewDefaultPolicyEngine()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	profile := ca.DefaultServerTLSProfile()

	// 1. Missing SAN when RequireSAN is true
	csrNoSAN := &x509.CertificateRequest{
		PublicKey: &key.PublicKey,
	}
	if err := policy.ValidateCSR(csrNoSAN, profile, 30*24*time.Hour); !errors.Is(err, ca.ErrSANRequired) {
		t.Fatalf("expected ErrSANRequired, got %v", err)
	}

	// 2. Excessive validity
	csrValid := &x509.CertificateRequest{
		PublicKey: &key.PublicKey,
		DNSNames:  []string{"secure.domain.com"},
	}
	err := policy.ValidateCSR(csrValid, profile, 450*24*time.Hour)
	if !errors.Is(err, ca.ErrValidityExceeded) {
		t.Fatalf("expected ErrValidityExceeded for 450-day validity, got %v", err)
	}
}

func TestPolicy_LintCertificate(t *testing.T) {
	policy := ca.NewDefaultPolicyEngine()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	profile := ca.DefaultServerTLSProfile()

	baseTmpl := func() *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(12345),
			NotBefore:             time.Now().Add(-1 * time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  false,
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:              []string{"api.domain.com"},
		}
	}

	// 1. Valid RSA certificate template
	results := policy.LintCertificate(baseTmpl(), &rsaKey.PublicKey, profile)
	if ca.HasLintErrors(results) {
		t.Fatalf("expected clean lint results for valid template, got: %+v", results)
	}

	// 2. Algorithm KeyUsage Mismatch: KeyEncipherment on ECDSA
	ecTmpl := baseTmpl()
	results = policy.LintCertificate(ecTmpl, &ecKey.PublicKey, profile)
	if !ca.HasLintErrors(results) {
		t.Fatalf("expected lint error for KeyEncipherment on ECDSA key")
	}

	// 3. Chronological Violation: NotBefore after NotAfter
	badTimeTmpl := baseTmpl()
	badTimeTmpl.NotBefore = time.Now().Add(24 * time.Hour)
	badTimeTmpl.NotAfter = time.Now()
	results = policy.LintCertificate(badTimeTmpl, &rsaKey.PublicKey, profile)
	if !ca.HasLintErrors(results) {
		t.Fatalf("expected lint error for NotBefore > NotAfter")
	}

	// 4. Non-positive Serial Number
	zeroSerialTmpl := baseTmpl()
	zeroSerialTmpl.SerialNumber = big.NewInt(0)
	results = policy.LintCertificate(zeroSerialTmpl, &rsaKey.PublicKey, profile)
	if !ca.HasLintErrors(results) {
		t.Fatalf("expected lint error for non-positive serial number")
	}

	// 5. CA KeyUsage missing CertSign
	caProfile := ca.DefaultSubCAProfile()
	badCATmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(12345),
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature, // missing CertSign
	}
	results = policy.LintCertificate(badCATmpl, &rsaKey.PublicKey, caProfile)
	if !ca.HasLintErrors(results) {
		t.Fatalf("expected lint error for CA without CertSign")
	}
}

func TestAuthority_PreIssuanceLintingRejection(t *testing.T) {
	auth := setupTestAuthority(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "ec.domain.com"},
		DNSNames: []string{"ec.domain.com"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, ecKey)
	if err != nil {
		t.Fatal(err)
	}

	// DefaultServerTLSProfile has KeyEncipherment, which is illegal for ECDSA keys
	profile := ca.DefaultServerTLSProfile()
	_, err = auth.SignCertificateWithProfile(
		csrDER,
		big.NewInt(12345),
		profile,
		ca.ExtensionConfig{},
		30*24*time.Hour,
		nil,
		nil,
	)
	if err == nil {
		t.Fatalf("expected pre-issuance lint failure for ECDSA with KeyEncipherment, got success")
	}
	if !errors.Is(err, ca.ErrLintFailure) {
		t.Fatalf("expected ErrLintFailure, got %v", err)
	}
}
