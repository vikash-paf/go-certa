package est

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"go-certa/pkg/ca"
	"go-certa/pkg/signer"
	"go-certa/pkg/storage"
)

type Handler struct {
	pool       *signer.WorkerPool
	cacertsPEM []byte
	store      storage.Storage
}

func NewHandler(pool *signer.WorkerPool, caCertDER []byte, stores ...storage.Storage) *Handler {
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	var store storage.Storage
	if len(stores) > 0 {
		store = stores[0]
	}
	return &Handler{
		pool:       pool,
		cacertsPEM: pemBlock,
		store:      store,
	}
}

func (h *Handler) HandleCACerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/pkcs7-mime")
	w.WriteHeader(http.StatusOK)
	w.Write(h.cacertsPEM)
}

func (h *Handler) HandleSimpleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	csrDER, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		http.Error(w, "body must be base64-encoded PKCS#10 CSR", http.StatusBadRequest)
		return
	}

	// Generate RFC 5280 compliant serial
	var serial *big.Int
	if h.store != nil {
		serial, err = ca.GenerateAndReserveSerial(r.Context(), h.store)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed allocating serial: %v", err), http.StatusInternalServerError)
			return
		}
	} else {
		serial, err = ca.GenerateSerial()
		if err != nil {
			serial = big.NewInt(time.Now().UnixNano())
		}
	}

	resChan := make(chan signer.SignResponse, 1)
	h.pool.Submit(signer.SignRequest{
		CSRDER:   csrDER,
		Serial:   serial,
		Validity: 90 * 24 * time.Hour,
		ResChan:  resChan,
	})

	res := <-resChan
	if res.Err != nil {
		http.Error(w, fmt.Sprintf("enrollment failed: %v", res.Err), http.StatusInternalServerError)
		return
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: res.CertDER})

	// Persist to storage if storage is configured
	if h.store != nil {
		if cert, err := x509.ParseCertificate(res.CertDER); err == nil {
			_ = h.store.SaveCertificate(r.Context(), &storage.CertificateRecord{
				Serial:    ca.FormatSerial(cert.SerialNumber),
				Subject:   cert.Subject.String(),
				Issuer:    cert.Issuer.String(),
				NotBefore: cert.NotBefore,
				NotAfter:  cert.NotAfter,
				RawDER:    res.CertDER,
				PEM:       pemBlock,
				Revoked:   false,
			})
		}
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	accept := strings.ToLower(r.Header.Get("Accept"))
	if format == "pem" || strings.Contains(accept, "application/x-pem-file") || strings.Contains(accept, "text/plain") {
		w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pemBlock)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-cert")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res.CertDER)
}
