package est

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"go-certa/pkg/signer"
)

type Handler struct {
	pool       *signer.WorkerPool
	cacertsPEM []byte
}

func NewHandler(pool *signer.WorkerPool, caCertDER []byte) *Handler {
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	return &Handler{
		pool:       pool,
		cacertsPEM: pemBlock,
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

	resChan := make(chan signer.SignResponse, 1)
	h.pool.Submit(signer.SignRequest{
		CSRDER:   csrDER,
		Serial:   big.NewInt(time.Now().UnixNano()),
		Validity: 90 * 24 * time.Hour,
		ResChan:  resChan,
	})

	res := <-resChan
	if res.Err != nil {
		http.Error(w, fmt.Sprintf("enrollment failed: %v", res.Err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-cert")
	w.WriteHeader(http.StatusOK)
	w.Write(res.CertDER)
}
