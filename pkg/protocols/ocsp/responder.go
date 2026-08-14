package ocsp

import (
	"crypto"
	"crypto/x509"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

type RevocationStore interface {
	IsRevoked(serial string) (bool, time.Time, int)
}

type MemoryRevocationStore struct {
	mu      sync.RWMutex
	revoked map[string]revocationRecord
}

type revocationRecord struct {
	revokedAt time.Time
	reason    int
}

func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{revoked: make(map[string]revocationRecord)}
}

func (s *MemoryRevocationStore) Revoke(serial string, reason int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[serial] = revocationRecord{revokedAt: time.Now(), reason: reason}
}

func (s *MemoryRevocationStore) IsRevoked(serial string) (bool, time.Time, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, exists := s.revoked[serial]
	return exists, rec.revokedAt, rec.reason
}

type Handler struct {
	issuerCert *x509.Certificate
	signer     crypto.Signer
	store      RevocationStore
}

func NewHandler(issuerCert *x509.Certificate, signer crypto.Signer, store RevocationStore) *Handler {
	return &Handler{
		issuerCert: issuerCert,
		signer:     signer,
		store:      store,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed reading request body", http.StatusBadRequest)
		return
	}

	ocspReq, err := ocsp.ParseRequest(body)
	if err != nil {
		http.Error(w, "malformed ocsp request", http.StatusBadRequest)
		return
	}

	serialStr := ocspReq.SerialNumber.String()
	isRevoked, revTime, reason := h.store.IsRevoked(serialStr)

	status := ocsp.Good
	if isRevoked {
		status = ocsp.Revoked
	}

	template := ocsp.Response{
		Status:           status,
		SerialNumber:     ocspReq.SerialNumber,
		ThisUpdate:       time.Now().Add(-1 * time.Minute),
		NextUpdate:       time.Now().Add(24 * time.Hour),
		RevokedAt:        revTime,
		RevocationReason: reason,
	}

	respDER, err := ocsp.CreateResponse(h.issuerCert, h.issuerCert, template, h.signer)
	if err != nil {
		http.Error(w, "failed generating ocsp response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	w.Write(respDER)
}
