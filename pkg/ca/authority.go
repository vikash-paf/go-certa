package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"go-certa/pkg/ctlog"
)

// Authority manages the CA trust anchor hierarchy (Root + Intermediate) and signs downstream certificates.
type Authority struct {
	RootCert         *x509.Certificate
	IntermediateCert *x509.Certificate
	Signer           crypto.Signer
	Policy           *PolicyEngine
}

// ComputeSubjectKeyID computes the RFC 5280 §4.2.1.2 Method (1) 160-bit SHA-1 hash of the public key bit string.
func ComputeSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	pkixBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(pkixBytes, &spki); err != nil {
		return nil, fmt.Errorf("failed to unmarshal subjectPublicKeyInfo: %w", err)
	}

	h := sha1.Sum(spki.PublicKey.Bytes)
	return h[:], nil
}

// NewAuthority initializes an in-memory Root and Intermediate CA hierarchy.
func NewAuthority(signer crypto.Signer) (*Authority, error) {
	// 1. Generate Root CA Key & Self-Signed Root Cert
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed generating root key: %w", err)
	}

	rootSKID, err := ComputeSubjectKeyID(&rootKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed computing root key id: %w", err)
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
		SubjectKeyId:          rootSKID,
		AuthorityKeyId:        rootSKID,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed creating root certificate: %w", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	// 2. Intermediate CA signed by Root
	intSKID, err := ComputeSubjectKeyID(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed computing intermediate key id: %w", err)
	}

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
		SubjectKeyId:          intSKID,
		AuthorityKeyId:        rootCert.SubjectKeyId,
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
		Policy:           NewDefaultPolicyEngine(),
	}, nil
}

// SignCertificate parses CSR, validates Proof-of-Possession, and mints an end-entity certificate
// using the standard Server TLS profile. Maintained for backward compatibility.
func (a *Authority) SignCertificate(csrDER []byte, serial *big.Int, validity time.Duration, dnsNames []string) ([]byte, error) {
	return a.SignCertificateWithProfile(csrDER, serial, DefaultServerTLSProfile(), ExtensionConfig{}, validity, dnsNames, nil)
}

// SignCertificateWithProfile issues an X.509 certificate adhering strictly to the requested ProfileConfig
// and embedding standard publication extensions (AIA and CDP).
func (a *Authority) SignCertificateWithProfile(
	csrDER []byte,
	serial *big.Int,
	profile ProfileConfig,
	extConfig ExtensionConfig,
	validity time.Duration,
	dnsNames []string,
	ipAddresses []net.IP,
) ([]byte, error) {
	if serial == nil || serial.Sign() <= 0 {
		return nil, errors.New("serial number must be a positive integer")
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("malformed csr: %w", err)
	}

	// 1. Verify Proof-of-Possession (Signature check using CSR's embedded public key)
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr proof-of-possession verification failed: %w", err)
	}

	policy := a.Policy
	if policy == nil {
		policy = NewDefaultPolicyEngine()
	}

	// 2. Validate Validity bounds
	if validity <= 0 {
		validity = profile.DefaultValidity
	}
	if profile.AllowedMaxValidity > 0 && validity > profile.AllowedMaxValidity {
		return nil, fmt.Errorf("%w: requested %v exceeds max %v", ErrValidityExceeded, validity, profile.AllowedMaxValidity)
	}

	// 3. Resolve Subject Alternative Names (SANs)
	sanDNS := csr.DNSNames
	if len(dnsNames) > 0 {
		sanDNS = dnsNames
	}

	sanIP := csr.IPAddresses
	if len(ipAddresses) > 0 {
		sanIP = ipAddresses
	}

	if profile.RequireSAN {
		if len(sanDNS) == 0 && len(sanIP) == 0 && len(csr.EmailAddresses) == 0 && len(csr.URIs) == 0 {
			return nil, ErrSANRequired
		}
	}

	// Validate public key and SAN names against PolicyEngine
	if err := policy.ValidatePublicKey(csr.PublicKey); err != nil {
		return nil, fmt.Errorf("public key policy validation failed: %w", err)
	}
	for _, d := range sanDNS {
		if err := policy.ValidateDNSName(d); err != nil {
			return nil, fmt.Errorf("dns name policy validation failed: %w", err)
		}
	}

	// 4. Calculate SubjectKeyId and AuthorityKeyId per RFC 5280 §4.2.1.1 & §4.2.1.2
	skid, err := ComputeSubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed computing subject key identifier: %w", err)
	}

	akid := a.IntermediateCert.SubjectKeyId
	if len(akid) == 0 {
		akid, _ = ComputeSubjectKeyID(a.IntermediateCert.PublicKey)
	}

	// Align KeyUsage to public key algorithm per RFC 5280 §4.2.1.3 and CA/B Forum BR §7.1.2.7.6:
	// For ECDSA and Ed25519 keys, KeyEncipherment MUST NOT be asserted.
	keyUsage := profile.KeyUsage
	switch csr.PublicKey.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey:
		if keyUsage&x509.KeyUsageDigitalSignature != 0 {
			keyUsage &^= x509.KeyUsageKeyEncipherment
		}
	}

	// 5. Assemble Certificate Template
	certTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              sanDNS,
		IPAddresses:           sanIP,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		NotBefore:             time.Now().Add(-5 * time.Minute), // Backdate 5m to counter clock skew
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           profile.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  profile.IsCA,
		MaxPathLen:            profile.MaxPathLen,
		MaxPathLenZero:        profile.MaxPathLenZero,
		SubjectKeyId:          skid,
		AuthorityKeyId:        akid,
		OCSPServer:            extConfig.OCSPServerURLs,
		IssuingCertificateURL: extConfig.IssuingCertificateURLs,
		CRLDistributionPoints: extConfig.CRLDistributionPoints,
	}

	// 6. Pre-Issuance Linting
	lintResults := policy.LintCertificate(certTmpl, csr.PublicKey, profile)
	if HasLintErrors(lintResults) {
		return nil, &LintErrors{Results: lintResults}
	}

	// 7. Sign Certificate using the Intermediate Signer (HSM)
	return x509.CreateCertificate(rand.Reader, certTmpl, a.IntermediateCert, csr.PublicKey, a.Signer)
}

// SignCertificateWithCT issues an end-entity certificate with embedded SCTs (RFC 6962).
// It constructs and signs a pre-certificate containing the critical CT Poison extension,
// submits it to the provided CT log submitters, serializes the collected SCTs,
// embeds them into the final certificate template (removing the poison extension),
// and produces the signed final certificate.
func (a *Authority) SignCertificateWithCT(
	ctx context.Context,
	csrDER []byte,
	serial *big.Int,
	profile ProfileConfig,
	extConfig ExtensionConfig,
	validity time.Duration,
	dnsNames []string,
	ctSubmitters []*ctlog.CTSubmitter,
) ([]byte, error) {
	if serial == nil || serial.Sign() <= 0 {
		return nil, errors.New("serial number must be a positive integer")
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("malformed csr: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr proof-of-possession verification failed: %w", err)
	}

	policy := a.Policy
	if policy == nil {
		policy = NewDefaultPolicyEngine()
	}

	if validity <= 0 {
		validity = profile.DefaultValidity
	}
	if profile.AllowedMaxValidity > 0 && validity > profile.AllowedMaxValidity {
		return nil, fmt.Errorf("%w: requested %v exceeds max %v", ErrValidityExceeded, validity, profile.AllowedMaxValidity)
	}

	sanDNS := csr.DNSNames
	if len(dnsNames) > 0 {
		sanDNS = dnsNames
	}

	if profile.RequireSAN && len(sanDNS) == 0 && len(csr.IPAddresses) == 0 && len(csr.EmailAddresses) == 0 && len(csr.URIs) == 0 {
		return nil, ErrSANRequired
	}

	if err := policy.ValidatePublicKey(csr.PublicKey); err != nil {
		return nil, fmt.Errorf("public key policy validation failed: %w", err)
	}
	for _, d := range sanDNS {
		if err := policy.ValidateDNSName(d); err != nil {
			return nil, fmt.Errorf("dns name policy validation failed: %w", err)
		}
	}

	skid, err := ComputeSubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed computing subject key identifier: %w", err)
	}

	akid := a.IntermediateCert.SubjectKeyId
	if len(akid) == 0 {
		akid, _ = ComputeSubjectKeyID(a.IntermediateCert.PublicKey)
	}

	// Align KeyUsage to public key algorithm per RFC 5280 §4.2.1.3 and CA/B Forum BR §7.1.2.7.6:
	// For ECDSA and Ed25519 keys, KeyEncipherment MUST NOT be asserted.
	keyUsage := profile.KeyUsage
	switch csr.PublicKey.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey:
		if keyUsage&x509.KeyUsageDigitalSignature != 0 {
			keyUsage &^= x509.KeyUsageKeyEncipherment
		}
	}

	certTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		DNSNames:              sanDNS,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           profile.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  profile.IsCA,
		MaxPathLen:            profile.MaxPathLen,
		MaxPathLenZero:        profile.MaxPathLenZero,
		SubjectKeyId:          skid,
		AuthorityKeyId:        akid,
		OCSPServer:            extConfig.OCSPServerURLs,
		IssuingCertificateURL: extConfig.IssuingCertificateURLs,
		CRLDistributionPoints: extConfig.CRLDistributionPoints,
	}

	lintResults := policy.LintCertificate(certTmpl, csr.PublicKey, profile)
	if HasLintErrors(lintResults) {
		return nil, &LintErrors{Results: lintResults}
	}

	// 1. Build and sign Pre-certificate with critical CT Poison extension
	preCertTmpl, err := ctlog.BuildPreCertificateTemplate(certTmpl)
	if err != nil {
		return nil, fmt.Errorf("failed building pre-certificate template: %w", err)
	}

	preCertDER, err := x509.CreateCertificate(rand.Reader, preCertTmpl, a.IntermediateCert, csr.PublicKey, a.Signer)
	if err != nil {
		return nil, fmt.Errorf("failed creating pre-certificate: %w", err)
	}

	// 2. Submit to CT logs and collect SCTs
	var scts [][]byte
	for _, submitter := range ctSubmitters {
		if submitter == nil {
			continue
		}
		sct, err := submitter.SubmitPreCertificate(ctx, preCertDER, a.IntermediateCert.Raw)
		if err != nil {
			return nil, fmt.Errorf("CT log submission to %s failed: %w", submitter.URL, err)
		}
		scts = append(scts, sct)
	}

	// 3. Serialize and embed SCT list into final certificate template
	if len(scts) > 0 {
		serializedList, err := ctlog.SerializeSCTList(scts)
		if err != nil {
			return nil, fmt.Errorf("failed serializing SCT list: %w", err)
		}
		ctlog.EmbedSCTList(certTmpl, serializedList)
	}

	// 4. Sign final certificate (without CT poison, with SCT list extension)
	return x509.CreateCertificate(rand.Reader, certTmpl, a.IntermediateCert, csr.PublicKey, a.Signer)
}
