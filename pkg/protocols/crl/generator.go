package crl

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"go-certa/pkg/storage"
)

var (
	// ErrNilIssuerCert indicates that the issuer certificate was not provided.
	ErrNilIssuerCert = errors.New("issuer certificate cannot be nil")

	// ErrNilSigner indicates that the cryptographic signer was not provided.
	ErrNilSigner = errors.New("signer cannot be nil")

	// ErrNilStorage indicates that the persistent storage backend was not provided.
	ErrNilStorage = errors.New("storage backend cannot be nil")

	// ErrCRLNotReady indicates that a CRL has not yet been generated.
	ErrCRLNotReady = errors.New("crl not yet generated")
)

// CRLGenerator produces signed RFC 5280 Certificate Revocation Lists.
type CRLGenerator struct {
	mu         sync.Mutex
	IssuerCert *x509.Certificate
	Signer     crypto.Signer
	Storage    storage.Storage
	Validity   time.Duration
	crlNumber  *big.Int
}

// NewCRLGenerator initializes a CRLGenerator with the given authority parameters and validity duration.
func NewCRLGenerator(
	issuerCert *x509.Certificate,
	signer crypto.Signer,
	store storage.Storage,
	validity time.Duration,
) (*CRLGenerator, error) {
	if issuerCert == nil {
		return nil, ErrNilIssuerCert
	}
	if signer == nil {
		return nil, ErrNilSigner
	}
	if store == nil {
		return nil, ErrNilStorage
	}
	if validity <= 0 {
		validity = 24 * time.Hour // Default 24 hours
	}

	return &CRLGenerator{
		IssuerCert: issuerCert,
		Signer:     signer,
		Storage:    store,
		Validity:   validity,
		crlNumber:  big.NewInt(0),
	}, nil
}

// GenerateCRL queries storage for all revoked certificates and builds a signed RFC 5280 CRL.
func (g *CRLGenerator) GenerateCRL(ctx context.Context) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// 1. Fetch all revocation records from storage
	records, err := g.Storage.ListRevoked(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed fetching revoked certificates: %w", err)
	}

	// 2. Convert to x509.RevocationListEntry
	entries := make([]x509.RevocationListEntry, 0, len(records))
	for _, rec := range records {
		normSerial := storage.NormalizeSerial(rec.Serial)
		serialInt, ok := new(big.Int).SetString(normSerial, 16)
		if !ok {
			return nil, fmt.Errorf("invalid hexadecimal serial in revocation record: %q", rec.Serial)
		}

		entry := x509.RevocationListEntry{
			SerialNumber:   serialInt,
			RevocationTime: rec.RevokedAt,
			ReasonCode:     rec.Reason,
		}
		entries = append(entries, entry)
	}

	// 3. Increment CRLNumber monotonically (RFC 5280 §5.2.3)
	g.crlNumber = new(big.Int).Add(g.crlNumber, big.NewInt(1))
	currentNumber := new(big.Int).Set(g.crlNumber)

	now := time.Now().UTC()
	thisUpdate := now.Add(-1 * time.Minute) // 1m backdate to tolerate clock skew
	nextUpdate := now.Add(g.Validity)

	// 4. Construct RevocationList template
	template := &x509.RevocationList{
		Number:                    currentNumber,
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}

	// 5. Sign CRL using issuer certificate and HSM / private signer
	crlDER, err := x509.CreateRevocationList(rand.Reader, template, g.IssuerCert, g.Signer)
	if err != nil {
		return nil, fmt.Errorf("failed creating signed revocation list: %w", err)
	}

	return crlDER, nil
}

// CRLService maintains periodic background regeneration of CRLs and serves the latest cached CRL.
type CRLService struct {
	mu            sync.RWMutex
	generator     *CRLGenerator
	interval      time.Duration
	cachedCRL     []byte
	lastGenerated time.Time
	stopCh        chan struct{}
	running       bool
}

// NewCRLService initializes a CRLService wrapping the provided generator.
func NewCRLService(generator *CRLGenerator, interval time.Duration) *CRLService {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &CRLService{
		generator: generator,
		interval:  interval,
		stopCh:    make(chan struct{}),
	}
}

// Regenerate issues a new CRL immediately and updates the in-memory cache.
func (s *CRLService) Regenerate(ctx context.Context) ([]byte, error) {
	crlDER, err := s.generator.GenerateCRL(ctx)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.cachedCRL = crlDER
	s.lastGenerated = time.Now().UTC()
	s.mu.Unlock()

	return crlDER, nil
}

// LatestCRL returns the most recently generated CRL DER bytes and its generation timestamp.
func (s *CRLService) LatestCRL() ([]byte, time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.cachedCRL) == 0 {
		return nil, time.Time{}, ErrCRLNotReady
	}

	// Return a defensive copy
	derCopy := make([]byte, len(s.cachedCRL))
	copy(derCopy, s.cachedCRL)
	return derCopy, s.lastGenerated, nil
}

// Start immediately generates an initial CRL and starts a background ticker to regenerate periodically.
func (s *CRLService) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	// Initial generation
	if _, err := s.Regenerate(ctx); err != nil {
		return fmt.Errorf("initial CRL generation failed: %w", err)
	}

	go func() {
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				_ = s.generator.mu.TryLock() // Non-blocking check or regular regenerate
				_, _ = s.Regenerate(context.Background())
			case <-s.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

// Stop halts the periodic regeneration goroutine.
func (s *CRLService) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}
	s.running = false
	close(s.stopCh)
}
