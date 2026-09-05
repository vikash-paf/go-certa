package storage

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	// ErrNotFound indicates that the requested certificate, revocation, or serial was not found.
	ErrNotFound = errors.New("record not found")

	// ErrAlreadyExists indicates an attempt to insert or reserve an existing certificate or serial.
	ErrAlreadyExists = errors.New("record already exists")

	// ErrAlreadyRevoked indicates that the certificate has already been revoked.
	ErrAlreadyRevoked = errors.New("certificate already revoked")

	// ErrInvalidInput indicates that an invalid parameter or empty serial was provided.
	ErrInvalidInput = errors.New("invalid input")
)

// Storage defines the persistent contract for storing certificates, revocations, and serial records.
type Storage interface {
	// SaveCertificate persists a new certificate record.
	SaveCertificate(ctx context.Context, cert *CertificateRecord) error

	// GetCertificate retrieves a certificate record by its serial number.
	GetCertificate(ctx context.Context, serial string) (*CertificateRecord, error)

	// RevokeCertificate marks a certificate as revoked and records the revocation details.
	RevokeCertificate(ctx context.Context, serial string, reason int, revokedAt time.Time) error

	// GetRevocation retrieves the revocation record for a serial number.
	GetRevocation(ctx context.Context, serial string) (*RevocationRecord, error)

	// ListRevoked returns all recorded revocations.
	ListRevoked(ctx context.Context) ([]*RevocationRecord, error)

	// ReserveSerial claims a serial number prior to certificate signing to prevent collisions.
	ReserveSerial(ctx context.Context, serial string) error
}

// NormalizeSerial strips optional '0x'/'0X' prefixes, trims whitespace, and converts to lowercase.
func NormalizeSerial(serial string) string {
	s := strings.TrimSpace(serial)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return strings.ToLower(s)
}
