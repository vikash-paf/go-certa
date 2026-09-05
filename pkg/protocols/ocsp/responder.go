package ocsp

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go-certa/pkg/storage"
	"golang.org/x/crypto/ocsp"
)

// RevocationStore provides backward-compatible revocation lookups.
type RevocationStore interface {
	IsRevoked(serial string) (bool, time.Time, int)
}

// MemoryRevocationStore is a simple in-memory store for backward compatibility.
type MemoryRevocationStore struct {
	mu      sync.RWMutex
	revoked map[string]revocationRecord
}

type revocationRecord struct {
	revokedAt time.Time
	reason    int
}

// NewMemoryRevocationStore initializes a new MemoryRevocationStore.
func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{revoked: make(map[string]revocationRecord)}
}

// Revoke records a certificate revocation.
func (s *MemoryRevocationStore) Revoke(serial string, reason int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[serial] = revocationRecord{revokedAt: time.Now().UTC(), reason: reason}
}

// IsRevoked checks if a serial is revoked.
func (s *MemoryRevocationStore) IsRevoked(serial string) (bool, time.Time, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, exists := s.revoked[serial]
	return exists, rec.revokedAt, rec.reason
}

// Config configures the OCSP Responder.
type Config struct {
	IssuerCert    *x509.Certificate // Intermediate CA certificate that issued the target certificates
	ResponderCert *x509.Certificate // Optional delegated responder certificate (with ExtKeyUsageOCSPSigning). Defaults to IssuerCert.
	Signer        crypto.Signer     // Private key matching ResponderCert (or IssuerCert)
	Storage       storage.Storage   // Persistent storage backend for real-time certificate & revocation state
	Store         RevocationStore   // Legacy revocation store (optional fallback)
	CacheMaxAge   int               // In seconds, defaults to 3600
	Validity      time.Duration     // OCSP response validity duration, defaults to 24h
}

// Handler serves OCSP requests conforming to RFC 6960 and RFC 5019.
type Handler struct {
	issuerCert    *x509.Certificate
	responderCert *x509.Certificate
	signer        crypto.Signer
	storage       storage.Storage
	store         RevocationStore
	cacheMaxAge   int
	validity      time.Duration
}

// NewHandler initializes a legacy OCSP handler (direct CA signing).
func NewHandler(issuerCert *x509.Certificate, signer crypto.Signer, store RevocationStore) *Handler {
	return &Handler{
		issuerCert:    issuerCert,
		responderCert: issuerCert,
		signer:        signer,
		store:         store,
		cacheMaxAge:   3600,
		validity:      24 * time.Hour,
	}
}

// NewResponder initializes an enhanced OCSP Responder supporting delegated signing and storage.
func NewResponder(cfg Config) (*Handler, error) {
	if cfg.IssuerCert == nil {
		return nil, errors.New("issuer certificate cannot be nil")
	}
	if cfg.Signer == nil {
		return nil, errors.New("signer cannot be nil")
	}

	responderCert := cfg.ResponderCert
	if responderCert == nil {
		responderCert = cfg.IssuerCert
	}

	cacheMaxAge := cfg.CacheMaxAge
	if cacheMaxAge <= 0 {
		cacheMaxAge = 3600
	}

	validity := cfg.Validity
	if validity <= 0 {
		validity = 24 * time.Hour
	}

	return &Handler{
		issuerCert:    cfg.IssuerCert,
		responderCert: responderCert,
		signer:        cfg.Signer,
		storage:       cfg.Storage,
		store:         cfg.Store,
		cacheMaxAge:   cacheMaxAge,
		validity:      validity,
	}, nil
}

// ServeHTTP handles both RFC 5019 HTTP GET/HEAD requests and RFC 6960 binary POST requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var reqBytes []byte
	var err error

	switch r.Method {
	case http.MethodPost:
		reqBytes, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed reading request body", http.StatusBadRequest)
			return
		}
	case http.MethodGet, http.MethodHead:
		// RFC 5019 §2.1: GET /{url-encoded-base64-ocsp-request}
		raw := r.URL.EscapedPath()
		if raw == "" {
			raw = r.URL.Path
		}
		for _, prefix := range []string{"/ocsp/", "/ocsp"} {
			if strings.HasPrefix(raw, prefix) {
				raw = strings.TrimPrefix(raw, prefix)
				break
			}
		}
		raw = strings.TrimPrefix(raw, "/")
		if raw == "" {
			raw = r.URL.RawQuery
		}
		if raw == "" {
			http.Error(w, "missing ocsp request in url", http.StatusBadRequest)
			return
		}

		unescaped, unerr := url.PathUnescape(raw)
		if unerr != nil {
			unescaped, unerr = url.QueryUnescape(raw)
			if unerr != nil {
				http.Error(w, "invalid url encoding", http.StatusBadRequest)
				return
			}
		}
		unescaped = strings.ReplaceAll(unescaped, " ", "+")

		reqBytes, err = base64.StdEncoding.DecodeString(unescaped)
		if err != nil {
			reqBytes, err = base64.URLEncoding.DecodeString(unescaped)
			if err != nil {
				reqBytes, err = base64.RawStdEncoding.DecodeString(unescaped)
				if err != nil {
					reqBytes, err = base64.RawURLEncoding.DecodeString(unescaped)
					if err != nil {
						http.Error(w, "invalid base64 ocsp request: "+err.Error(), http.StatusBadRequest)
						return
					}
				}
			}
		}
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ocspReq, err := ocsp.ParseRequest(reqBytes)
	if err != nil {
		http.Error(w, "malformed ocsp request", http.StatusBadRequest)
		return
	}

	// Determine status
	status := ocsp.Good
	var revTime time.Time
	var reason int

	if h.storage != nil {
		serialHex := storage.NormalizeSerial(ocspReq.SerialNumber.Text(16))
		cert, err := h.storage.GetCertificate(r.Context(), serialHex)
		if errors.Is(err, storage.ErrNotFound) {
			status = ocsp.Unknown
		} else if err != nil {
			http.Error(w, "internal storage error", http.StatusInternalServerError)
			return
		} else if cert.Revoked {
			status = ocsp.Revoked
			revRec, err := h.storage.GetRevocation(r.Context(), serialHex)
			if err == nil {
				revTime = revRec.RevokedAt
				reason = revRec.Reason
			}
		} else {
			status = ocsp.Good
		}
	} else if h.store != nil {
		serialStr := ocspReq.SerialNumber.String()
		isRevoked, rTime, rReason := h.store.IsRevoked(serialStr)
		if isRevoked {
			status = ocsp.Revoked
			revTime = rTime
			reason = rReason
		} else {
			status = ocsp.Good
		}
	}

	now := time.Now().UTC()
	thisUpdate := now.Add(-1 * time.Minute)
	nextUpdate := now.Add(h.validity)

	template := ocsp.Response{
		Status:           status,
		SerialNumber:     ocspReq.SerialNumber,
		ThisUpdate:       thisUpdate,
		NextUpdate:       nextUpdate,
		RevokedAt:        revTime,
		RevocationReason: reason,
		Certificate:      h.responderCert,
	}

	// Create Response signed by ResponderCert (embedded in response) with h.signer
	respDER, err := ocsp.CreateResponse(h.issuerCert, h.responderCert, template, h.signer)
	if err != nil {
		http.Error(w, "failed generating ocsp response", http.StatusInternalServerError)
		return
	}

	// RFC 5019 Caching and ETag headers
	etag := fmt.Sprintf("\"%x\"", sha256.Sum256(respDER))
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, no-transform, must-revalidate", h.cacheMaxAge))
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", thisUpdate.Format(http.TimeFormat))

	// Handle conditional HTTP GET
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch != "" && (ifNoneMatch == etag || ifNoneMatch == "*") {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respDER)
}
