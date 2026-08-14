package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// Authority manages the CA trust anchor hierarchy (Root + Intermediate) and signs downstream certificates.
type Authority struct {
	RootCert         *x509.Certificate
	IntermediateCert *x509.Certificate
	Signer           crypto.Signer
}

// NewAuthority initializes an in-memory Root and Intermediate CA hierarchy.
func NewAuthority(signer crypto.Signer) (*Authority, error) {
	// 1. Generate Root CA Key & Self-Signed Root Cert
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed generating root key: %w", err)
	}

	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Go-Certa Trust Network"},
			CommonName:   "Go-Certa Root CA G1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed creating root certificate: %w", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	// 2. Intermediate CA signed by Root
	intTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Go-Certa Trust Network"},
			CommonName:   "Go-Certa Issuing Intermediate CA 1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true, // Cannot issue downstream intermediate CAs
	}

	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, signer.Public(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed creating intermediate certificate: %w", err)
	}
	intCert, _ := x509.ParseCertificate(intDER)

	return &Authority{
		RootCert:         rootCert,
		IntermediateCert: intCert,
		Signer:           signer,
	}, nil
}

// SignCertificate parses CSR, validates Proof-of-Possession, and mints an end-entity certificate.
func (a *Authority) SignCertificate(csrDER []byte, serial *big.Int, validity time.Duration, dnsNames []string) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("malformed csr: %w", err)
	}

	// 1. Verify Proof-of-Possession (Signature check using CSR's embedded public key)
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr proof-of-possession verification failed: %w", err)
	}

	// 2. Determine SAN DNS Names (overridden by domain policy/challenges if applicable)
	sanList := csr.DNSNames
	if len(dnsNames) > 0 {
		sanList = dnsNames
	}

	// 3. Assemble standard RFC 5280 End-Entity Certificate Template
	certTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              sanList,
		IPAddresses:           csr.IPAddresses,
		NotBefore:             time.Now().Add(-5 * time.Minute), // Backdate 5m to counter clock skew
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// 4. Create Certificate using the Intermediate Signer (HSM)
	return x509.CreateCertificate(rand.Reader, certTmpl, a.IntermediateCert, csr.PublicKey, a.Signer)
}
