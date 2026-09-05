package acme

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// NonceManager manages single-use anti-replay nonces per RFC 8555 §6.5.
type NonceManager struct {
	mu     sync.Mutex
	nonces map[string]time.Time
	ttl    time.Duration
}

// NewNonceManager constructs a NonceManager with the specified nonce lifetime.
func NewNonceManager(ttl time.Duration) *NonceManager {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &NonceManager{
		nonces: make(map[string]time.Time),
		ttl:    ttl,
	}
}

// GenerateNonce creates a fresh 128-bit cryptographically random, base64url-encoded nonce.
func (m *NonceManager) GenerateNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	nonce := base64.RawURLEncoding.EncodeToString(buf)

	m.mu.Lock()
	m.nonces[nonce] = time.Now().UTC().Add(m.ttl)
	m.mu.Unlock()

	return nonce, nil
}

// ValidateAndConsumeNonce verifies that the nonce exists, has not expired, and consumes it (single-use).
func (m *NonceManager) ValidateAndConsumeNonce(nonce string) bool {
	if nonce == "" {
		return false
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	expiry, exists := m.nonces[nonce]
	if !exists {
		return false
	}

	// Always delete upon lookup (strictly single-use)
	delete(m.nonces, nonce)

	return time.Now().UTC().Before(expiry)
}

// Cleanup removes any expired nonces from memory.
func (m *NonceManager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	for n, exp := range m.nonces {
		if now.After(exp) {
			delete(m.nonces, n)
		}
	}
}
