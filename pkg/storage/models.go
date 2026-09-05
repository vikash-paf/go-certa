package storage

import (
	"time"
)

// RFC 5280 CRLReason codes as defined in Section 5.3.1.
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonCACompromise         = 2
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
	ReasonCertificateHold      = 6
	ReasonRemoveFromCRL        = 8
	ReasonPrivilegeWithdrawn   = 9
	ReasonAACompromise         = 10
)

// CertificateRecord represents a persisted X.509 certificate and its operational metadata.
type CertificateRecord struct {
	Serial    string    `json:"serial"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	RawDER    []byte    `json:"raw_der"`
	PEM       []byte    `json:"pem"`
	Revoked   bool      `json:"revoked"`
}

// RevocationRecord captures revocation metadata for a revoked certificate.
type RevocationRecord struct {
	Serial    string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    int       `json:"reason"`
}

// SerialRecord records an allocated or issued certificate serial number.
type SerialRecord struct {
	Serial   string    `json:"serial"`
	IssuedAt time.Time `json:"issued_at"`
}
