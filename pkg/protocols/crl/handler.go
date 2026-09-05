package crl

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

// CRLProvider abstracts retrieving the latest CRL DER payload and metadata.
type CRLProvider interface {
	LatestCRL() ([]byte, time.Time, error)
}

// Handler serves CRLs over HTTP conforming to RFC 5280 and RFC 2585.
type Handler struct {
	provider    CRLProvider
	cacheMaxAge int
}

// HandlerOption configures Handler options.
type HandlerOption func(*Handler)

// WithCacheMaxAge sets the max-age in seconds for the Cache-Control header.
func WithCacheMaxAge(seconds int) HandlerOption {
	return func(h *Handler) {
		if seconds > 0 {
			h.cacheMaxAge = seconds
		}
	}
}

// NewHandler creates a new HTTP Handler for serving CRLs.
func NewHandler(provider CRLProvider, opts ...HandlerOption) *Handler {
	h := &Handler{
		provider:    provider,
		cacheMaxAge: 3600, // 1 hour default
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// ServeHTTP handles HTTP GET and HEAD requests for the CRL binary.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	crlDER, lastGen, err := h.provider.LatestCRL()
	if err != nil {
		if errors.Is(err, ErrCRLNotReady) {
			http.Error(w, "CRL Not Ready", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(h.cacheMaxAge)+", must-revalidate")
	if !lastGen.IsZero() {
		w.Header().Set("Last-Modified", lastGen.UTC().Format(http.TimeFormat))
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(crlDER)))

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(crlDER)
}
