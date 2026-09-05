package ca

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// ProfileType represents the canonical identifier of a certificate issuance profile.
type ProfileType string

const (
	// ProfileServerTLS represents the standard Server TLS profile (RFC 5280 & CA/B Forum BR).
	ProfileServerTLS ProfileType = "server-tls"

	// ProfileClientAuth represents the mTLS Client Authentication profile.
	ProfileClientAuth ProfileType = "client-auth"

	// ProfileCodeSigning represents the executable and artifact Code Signing profile.
	ProfileCodeSigning ProfileType = "code-signing"

	// ProfileSubCA represents the Subordinate / Issuing Intermediate CA profile.
	ProfileSubCA ProfileType = "sub-ca"
)

var (
	// ErrUnknownProfile is returned when requesting a profile that does not exist.
	ErrUnknownProfile = errors.New("unknown certificate profile")

	// ErrValidityExceeded is returned when the requested validity duration exceeds the profile's allowed ceiling.
	ErrValidityExceeded = errors.New("requested validity exceeds maximum allowed by profile")

	// ErrSANRequired is returned when a profile requires at least one Subject Alternative Name but none was provided.
	ErrSANRequired = errors.New("profile requires at least one Subject Alternative Name (SAN)")
)

// ProfileConfig encapsulates the policy and X.509 extension constraints for a certificate profile.
type ProfileConfig struct {
	ProfileType        ProfileType
	Description        string
	AllowedMaxValidity time.Duration
	DefaultValidity    time.Duration
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage
	IsCA               bool
	MaxPathLen         int
	MaxPathLenZero     bool
	RequireSAN         bool
}

// ExtensionConfig specifies authority-level publication URLs to be injected into standard extensions.
type ExtensionConfig struct {
	// OCSPServerURLs populates Authority Information Access (AIA) id-ad-ocsp (RFC 5280 §4.2.2.1).
	OCSPServerURLs []string

	// IssuingCertificateURLs populates Authority Information Access (AIA) id-ad-caIssuers (RFC 5280 §4.2.2.1).
	IssuingCertificateURLs []string

	// CRLDistributionPoints populates CRL Distribution Points (CDP) (RFC 5280 §4.2.1.13).
	CRLDistributionPoints []string
}

// DefaultServerTLSProfile returns the standard TLS server profile conforming to RFC 5280 and CA/B Forum BR.
func DefaultServerTLSProfile() ProfileConfig {
	return ProfileConfig{
		ProfileType:        ProfileServerTLS,
		Description:        "Standard TLS Server Profile (RFC 5280 / CA/B Forum BR)",
		AllowedMaxValidity: 398 * 24 * time.Hour, // Max 398 days per CA/B Forum BR
		DefaultValidity:    90 * 24 * time.Hour,  // 90-day recommended cadence
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:               false,
		RequireSAN:         true,
	}
}

// DefaultClientAuthProfile returns the profile for client mTLS authentication.
func DefaultClientAuthProfile() ProfileConfig {
	return ProfileConfig{
		ProfileType:        ProfileClientAuth,
		Description:        "Client Authentication Profile (mTLS)",
		AllowedMaxValidity: 730 * 24 * time.Hour, // 2 years
		DefaultValidity:    365 * 24 * time.Hour, // 1 year
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:               false,
		RequireSAN:         false,
	}
}

// DefaultCodeSigningProfile returns the profile for signing software binaries and scripts.
func DefaultCodeSigningProfile() ProfileConfig {
	return ProfileConfig{
		ProfileType:        ProfileCodeSigning,
		Description:        "Code Signing Profile (RFC 5280)",
		AllowedMaxValidity: 1095 * 24 * time.Hour, // 3 years
		DefaultValidity:    365 * 24 * time.Hour,  // 1 year
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		IsCA:               false,
		RequireSAN:         false,
	}
}

// DefaultSubCAProfile returns the profile for issuing subordinate / intermediate CAs.
func DefaultSubCAProfile() ProfileConfig {
	return ProfileConfig{
		ProfileType:        ProfileSubCA,
		Description:        "Subordinate Issuing Intermediate CA Profile",
		AllowedMaxValidity: 10 * 365 * 24 * time.Hour, // 10 years
		DefaultValidity:    5 * 365 * 24 * time.Hour,  // 5 years
		KeyUsage:           x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:        nil,
		IsCA:               true,
		MaxPathLen:         0,
		MaxPathLenZero:     true,
		RequireSAN:         false,
	}
}

// GetProfile resolves a ProfileType to its corresponding ProfileConfig preset.
func GetProfile(name ProfileType) (*ProfileConfig, error) {
	switch name {
	case ProfileServerTLS:
		p := DefaultServerTLSProfile()
		return &p, nil
	case ProfileClientAuth:
		p := DefaultClientAuthProfile()
		return &p, nil
	case ProfileCodeSigning:
		p := DefaultCodeSigningProfile()
		return &p, nil
	case ProfileSubCA:
		p := DefaultSubCAProfile()
		return &p, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownProfile, name)
	}
}
