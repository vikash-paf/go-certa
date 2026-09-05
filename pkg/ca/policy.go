package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	// ErrWeakRSAKey indicates that the RSA key does not meet the minimum required modulus bit length.
	ErrWeakRSAKey = errors.New("RSA key size is below minimum allowed")

	// ErrUnsupportedKey indicates that the public key type or elliptic curve is not permitted.
	ErrUnsupportedKey = errors.New("unsupported public key type or curve")

	// ErrForbiddenDNSName indicates that the requested domain name contains a forbidden suffix or label.
	ErrForbiddenDNSName = errors.New("domain name contains forbidden label or TLD")

	// ErrInvalidWildcard indicates that the wildcard specification violates policy or RFC rules.
	ErrInvalidWildcard = errors.New("wildcard domain violates policy")

	// ErrLintFailure indicates that the certificate template violated one or more linting rules.
	ErrLintFailure = errors.New("certificate failed pre-issuance linting")
)

// LintLevel specifies the severity of a lint check result.
type LintLevel string

const (
	// LintError represents a fatal lint violation that blocks certificate issuance.
	LintError LintLevel = "ERROR"

	// LintWarning represents a non-fatal warning or advisory note.
	LintWarning LintLevel = "WARNING"

	// LintInfo represents an informational note.
	LintInfo LintLevel = "INFO"
)

// LintResult captures the outcome of an individual lint check.
type LintResult struct {
	Rule    string    `json:"rule"`
	Level   LintLevel `json:"level"`
	Message string    `json:"message"`
}

// LintErrors wraps multiple lint results that failed issuance.
type LintErrors struct {
	Results []LintResult
}

func (e *LintErrors) Error() string {
	var msgs []string
	for _, r := range e.Results {
		if r.Level == LintError {
			msgs = append(msgs, fmt.Sprintf("[%s] %s", r.Rule, r.Message))
		}
	}
	return fmt.Sprintf("%v: %s", ErrLintFailure, strings.Join(msgs, "; "))
}

func (e *LintErrors) Unwrap() error {
	return ErrLintFailure
}

// HasLintErrors returns true if any result in the list has LintError severity.
func HasLintErrors(results []LintResult) bool {
	for _, r := range results {
		if r.Level == LintError {
			return true
		}
	}
	return false
}

// PolicyEngine enforces pre-issuance validation rules and linting checks.
type PolicyEngine struct {
	MaxValidityDuration  time.Duration
	AllowWildcards       bool
	AllowInternalDomains bool
	MinRSAKeySize        int
	AllowedECCurves      []elliptic.Curve
	DisallowedDNSNames   []string
	RequireDNSOrIP       bool
}

// NewDefaultPolicyEngine initializes a PolicyEngine with standard CA/B Forum and RFC 5280 constraints.
func NewDefaultPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		MaxValidityDuration: 398 * 24 * time.Hour, // Max 398 days for TLS
		AllowWildcards:      true,
		MinRSAKeySize:       2048,
		AllowedECCurves: []elliptic.Curve{
			elliptic.P256(),
			elliptic.P384(),
			elliptic.P521(),
		},
		DisallowedDNSNames: []string{
			"localhost",
			".local",
			".internal",
			".lan",
			".onion",
			".test",
			".invalid",
			".example",
		},
		RequireDNSOrIP: true,
	}
}

// ValidateCSR verifies that the CSR meets all cryptographic and identifier policy rules.
func (p *PolicyEngine) ValidateCSR(csr *x509.CertificateRequest, profile ProfileConfig, validity time.Duration) error {
	if csr == nil {
		return errors.New("csr cannot be nil")
	}

	// 1. Public Key Policy Checks
	if err := p.ValidatePublicKey(csr.PublicKey); err != nil {
		return err
	}

	// 2. Validity Duration Check
	if validity <= 0 {
		validity = profile.DefaultValidity
	}
	if p.MaxValidityDuration > 0 && validity > p.MaxValidityDuration {
		return fmt.Errorf("%w: requested %v exceeds policy max %v", ErrValidityExceeded, validity, p.MaxValidityDuration)
	}
	if profile.AllowedMaxValidity > 0 && validity > profile.AllowedMaxValidity {
		return fmt.Errorf("%w: requested %v exceeds profile max %v", ErrValidityExceeded, validity, profile.AllowedMaxValidity)
	}

	// 3. DNS Names & Wildcards Policy Checks
	for _, dns := range csr.DNSNames {
		if err := p.ValidateDNSName(dns); err != nil {
			return err
		}
	}

	// 4. SAN Requirement Checks
	if profile.RequireSAN || (p.RequireDNSOrIP && profile.ProfileType == ProfileServerTLS) {
		if len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0 && len(csr.EmailAddresses) == 0 && len(csr.URIs) == 0 {
			return ErrSANRequired
		}
	}

	return nil
}

// ValidatePublicKey verifies key type, minimum bit length, and allowed curves.
func (p *PolicyEngine) ValidatePublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		bitLen := k.N.BitLen()
		if bitLen < p.MinRSAKeySize {
			return fmt.Errorf("%w: RSA modulus size %d is less than required %d", ErrWeakRSAKey, bitLen, p.MinRSAKeySize)
		}
		if k.E < 65537 {
			return fmt.Errorf("RSA public exponent %d is insecure (minimum 65537 required)", k.E)
		}
		return nil

	case *ecdsa.PublicKey:
		curveMatch := false
		kParams := k.Curve.Params()
		for _, allowed := range p.AllowedECCurves {
			if kParams.Name == allowed.Params().Name {
				curveMatch = true
				break
			}
		}
		if !curveMatch {
			return fmt.Errorf("%w: elliptic curve %q not in allowed list", ErrUnsupportedKey, kParams.Name)
		}
		if !k.Curve.IsOnCurve(k.X, k.Y) {
			return fmt.Errorf("%w: public key point is not on curve %q", ErrUnsupportedKey, kParams.Name)
		}
		return nil

	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: invalid ed25519 public key length", ErrUnsupportedKey)
		}
		return nil

	default:
		return fmt.Errorf("%w: algorithm %T not supported", ErrUnsupportedKey, pub)
	}
}

// ValidateDNSName validates wildcard placement, forbidden suffixes, and format.
func (p *PolicyEngine) ValidateDNSName(name string) error {
	trimmed := strings.TrimSpace(strings.ToLower(name))
	if trimmed == "" {
		return fmt.Errorf("%w: empty DNS name", ErrForbiddenDNSName)
	}

	// Disallowed DNS names or suffixes
	for _, disallowed := range p.DisallowedDNSNames {
		if p.AllowInternalDomains && isInternalDomainSuffix(disallowed) {
			continue
		}
		if trimmed == disallowed || strings.HasSuffix(trimmed, disallowed) {
			return fmt.Errorf("%w: domain %q matches disallowed suffix %q", ErrForbiddenDNSName, name, disallowed)
		}
	}

	// Wildcard checks
	if strings.Contains(trimmed, "*") {
		if !p.AllowWildcards {
			return fmt.Errorf("%w: wildcards are disabled by policy: %q", ErrInvalidWildcard, name)
		}

		// CABF BR §7.1.4.2.1: Wildcards MUST be the entire leftmost label
		if !strings.HasPrefix(trimmed, "*.") {
			return fmt.Errorf("%w: wildcard character must be the entire leftmost label (*.example.com): %q", ErrInvalidWildcard, name)
		}

		remainder := strings.TrimPrefix(trimmed, "*.")
		if remainder == "" || !strings.Contains(remainder, ".") {
			return fmt.Errorf("%w: wildcard cannot directly precede a public TLD (*.com): %q", ErrInvalidWildcard, name)
		}

		// Ensure no other asterisks exist
		if strings.Contains(remainder, "*") {
			return fmt.Errorf("%w: multiple wildcards in domain name: %q", ErrInvalidWildcard, name)
		}
	}

	return nil
}

// LintCertificate executes pre-issuance lint checks on the prepared certificate template.
func (p *PolicyEngine) LintCertificate(cert *x509.Certificate, pubKey crypto.PublicKey, profile ProfileConfig) []LintResult {
	var results []LintResult

	// 1. Serial Number Constraints (RFC 5280 §4.1.2.2)
	if cert.SerialNumber == nil {
		results = append(results, LintResult{
			Rule:    "serial-not-nil",
			Level:   LintError,
			Message: "certificate serial number cannot be nil",
		})
	} else {
		if cert.SerialNumber.Sign() <= 0 {
			results = append(results, LintResult{
				Rule:    "serial-positive",
				Level:   LintError,
				Message: fmt.Sprintf("serial number must be positive (got %v)", cert.SerialNumber),
			})
		}
		if cert.SerialNumber.BitLen() > MaxSerialBits {
			results = append(results, LintResult{
				Rule:    "serial-20-octets",
				Level:   LintError,
				Message: fmt.Sprintf("serial number length %d bits exceeds 159 bits (20 octets limit)", cert.SerialNumber.BitLen()),
			})
		}
	}

	// 2. Validity Time Ordering
	if !cert.NotBefore.Before(cert.NotAfter) {
		results = append(results, LintResult{
			Rule:    "validity-chronological",
			Level:   LintError,
			Message: fmt.Sprintf("NotBefore (%v) must be before NotAfter (%v)", cert.NotBefore, cert.NotAfter),
		})
	}

	// 3. BasicConstraints Conformance
	if !cert.BasicConstraintsValid {
		results = append(results, LintResult{
			Rule:    "basic-constraints-valid",
			Level:   LintError,
			Message: "BasicConstraints extension must be marked valid",
		})
	}
	if cert.IsCA != profile.IsCA {
		results = append(results, LintResult{
			Rule:    "basic-constraints-is-ca",
			Level:   LintError,
			Message: fmt.Sprintf("certificate IsCA (%t) does not match profile IsCA (%t)", cert.IsCA, profile.IsCA),
		})
	}

	// 4. Algorithm & KeyUsage Alignment (RFC 5280 §4.2.1.3)
	if pubKey != nil {
		switch pubKey.(type) {
		case *ecdsa.PublicKey, ed25519.PublicKey:
			if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
				results = append(results, LintResult{
					Rule:    "key-usage-algorithm-alignment",
					Level:   LintError,
					Message: "KeyEncipherment KeyUsage is forbidden for ECDSA / Ed25519 keys",
				})
			}
		}
	}

	if cert.IsCA {
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			results = append(results, LintResult{
				Rule:    "ca-key-usage-cert-sign",
				Level:   LintError,
				Message: "CA certificate KeyUsage must include CertSign",
			})
		}
	}

	// 5. SAN Requirement Check
	if profile.RequireSAN {
		if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 && len(cert.EmailAddresses) == 0 && len(cert.URIs) == 0 {
			results = append(results, LintResult{
				Rule:    "san-present",
				Level:   LintError,
				Message: "profile requires at least one Subject Alternative Name",
			})
		}
	}

	// 6. ExtKeyUsage Conformance
	if profile.ProfileType == ProfileServerTLS {
		hasServerAuth := false
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageServerAuth {
				hasServerAuth = true
				break
			}
		}
		if !hasServerAuth {
			results = append(results, LintResult{
				Rule:    "server-tls-eku",
				Level:   LintError,
				Message: "Server TLS profile must include ServerAuth in ExtKeyUsage",
			})
		}
	}

	return results
}

func isInternalDomainSuffix(suffix string) bool {
	switch suffix {
	case "localhost", ".local", ".internal", ".lan", ".test", ".invalid", ".example":
		return true
	default:
		return false
	}
}
