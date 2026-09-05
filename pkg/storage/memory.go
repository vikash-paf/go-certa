package storage

import (
	"context"
	"sort"
	"sync"
	"time"
)

var _ Storage = (*MemoryStorage)(nil)

// MemoryStorage is a thread-safe, in-memory implementation of the Storage interface.
type MemoryStorage struct {
	mu           sync.RWMutex
	certificates map[string]*CertificateRecord
	revocations  map[string]*RevocationRecord
	serials      map[string]*SerialRecord
}

// NewMemoryStorage initializes an empty, thread-safe in-memory certificate store.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		certificates: make(map[string]*CertificateRecord),
		revocations:  make(map[string]*RevocationRecord),
		serials:      make(map[string]*SerialRecord),
	}
}

// SaveCertificate persists a new certificate record. It returns ErrAlreadyExists if
// a certificate with the same serial is already stored.
func (m *MemoryStorage) SaveCertificate(ctx context.Context, cert *CertificateRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if cert == nil {
		return ErrInvalidInput
	}

	normSerial := NormalizeSerial(cert.Serial)
	if normSerial == "" {
		return ErrInvalidInput
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.certificates[normSerial]; exists {
		return ErrAlreadyExists
	}

	// If the serial was not explicitly reserved prior to save, record it now.
	if _, exists := m.serials[normSerial]; !exists {
		m.serials[normSerial] = &SerialRecord{
			Serial:   normSerial,
			IssuedAt: time.Now().UTC(),
		}
	}

	m.certificates[normSerial] = cloneCertificate(cert, normSerial)
	return nil
}

// GetCertificate retrieves a certificate record by serial number.
func (m *MemoryStorage) GetCertificate(ctx context.Context, serial string) (*CertificateRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	normSerial := NormalizeSerial(serial)
	if normSerial == "" {
		return nil, ErrInvalidInput
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	cert, exists := m.certificates[normSerial]
	if !exists {
		return nil, ErrNotFound
	}

	return cloneCertificate(cert, normSerial), nil
}

// RevokeCertificate marks a certificate as revoked and records the revocation metadata.
func (m *MemoryStorage) RevokeCertificate(ctx context.Context, serial string, reason int, revokedAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	normSerial := NormalizeSerial(serial)
	if normSerial == "" {
		return ErrInvalidInput
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	cert, exists := m.certificates[normSerial]
	if !exists {
		return ErrNotFound
	}

	if cert.Revoked {
		return ErrAlreadyRevoked
	}
	if _, alreadyRevoked := m.revocations[normSerial]; alreadyRevoked {
		return ErrAlreadyRevoked
	}

	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	}

	cert.Revoked = true
	m.revocations[normSerial] = &RevocationRecord{
		Serial:    normSerial,
		RevokedAt: revokedAt,
		Reason:    reason,
	}

	return nil
}

// GetRevocation retrieves the revocation record for a given serial number.
func (m *MemoryStorage) GetRevocation(ctx context.Context, serial string) (*RevocationRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	normSerial := NormalizeSerial(serial)
	if normSerial == "" {
		return nil, ErrInvalidInput
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	rev, exists := m.revocations[normSerial]
	if !exists {
		return nil, ErrNotFound
	}

	return cloneRevocation(rev), nil
}

// ListRevoked returns all recorded revocations sorted chronologically by RevokedAt.
func (m *MemoryStorage) ListRevoked(ctx context.Context) ([]*RevocationRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*RevocationRecord, 0, len(m.revocations))
	for _, rev := range m.revocations {
		result = append(result, cloneRevocation(rev))
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].RevokedAt.Equal(result[j].RevokedAt) {
			return result[i].Serial < result[j].Serial
		}
		return result[i].RevokedAt.Before(result[j].RevokedAt)
	})

	return result, nil
}

// ReserveSerial claims a serial number prior to certificate generation to prevent race conditions.
func (m *MemoryStorage) ReserveSerial(ctx context.Context, serial string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	normSerial := NormalizeSerial(serial)
	if normSerial == "" {
		return ErrInvalidInput
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.serials[normSerial]; exists {
		return ErrAlreadyExists
	}
	if _, exists := m.certificates[normSerial]; exists {
		return ErrAlreadyExists
	}

	m.serials[normSerial] = &SerialRecord{
		Serial:   normSerial,
		IssuedAt: time.Now().UTC(),
	}

	return nil
}

// cloneCertificate performs a deep copy of a CertificateRecord to preserve immutability.
func cloneCertificate(src *CertificateRecord, normSerial string) *CertificateRecord {
	dst := *src
	dst.Serial = normSerial

	if src.RawDER != nil {
		dst.RawDER = make([]byte, len(src.RawDER))
		copy(dst.RawDER, src.RawDER)
	}

	if src.PEM != nil {
		dst.PEM = make([]byte, len(src.PEM))
		copy(dst.PEM, src.PEM)
	}

	return &dst
}

// cloneRevocation performs a copy of a RevocationRecord.
func cloneRevocation(src *RevocationRecord) *RevocationRecord {
	dst := *src
	return &dst
}
