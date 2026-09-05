package ocsp

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"go-certa/pkg/storage"
)

// RevokeRequest represents the JSON request body for certificate revocation.
type RevokeRequest struct {
	Serial string `json:"serial"`
	Reason int    `json:"reason"`
}

// RevokeResponse represents the JSON response returned after successful revocation.
type RevokeResponse struct {
	Status    string    `json:"status"`
	Serial    string    `json:"serial"`
	Reason    int       `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

// RevocationAPI manages HTTP endpoints for revocation operations.
type RevocationAPI struct {
	storage storage.Storage
}

// NewRevocationAPI constructs a new RevocationAPI backed by storage.Storage.
func NewRevocationAPI(store storage.Storage) *RevocationAPI {
	return &RevocationAPI{storage: store}
}

// HandleRevoke processes POST requests to revoke an issued certificate.
func (api *RevocationAPI) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON payload"})
		return
	}

	normSerial := storage.NormalizeSerial(req.Serial)
	if normSerial == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "serial is required"})
		return
	}

	now := time.Now().UTC()
	err := api.storage.RevokeCertificate(r.Context(), normSerial, req.Reason, now)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, storage.ErrNotFound) {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "certificate not found"})
			return
		}
		if errors.Is(err, storage.ErrAlreadyRevoked) {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "certificate already revoked"})
			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error revoking certificate"})
		return
	}

	revRec, err := api.storage.GetRevocation(r.Context(), normSerial)
	revTime := now
	if err == nil && !revRec.RevokedAt.IsZero() {
		revTime = revRec.RevokedAt
	}

	resp := RevokeResponse{
		Status:    "revoked",
		Serial:    normSerial,
		Reason:    req.Reason,
		RevokedAt: revTime,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ServeHTTP implements http.Handler delegating to HandleRevoke.
func (api *RevocationAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	api.HandleRevoke(w, r)
}
