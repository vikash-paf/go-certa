package ctlog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"time"
)

// MockCTLog represents an in-memory RFC 6962 compliant Certificate Transparency Log.
type MockCTLog struct {
	Key    *ecdsa.PrivateKey
	LogID  [32]byte
	Server *httptest.Server
}

// NewMockCTLogServer initializes and starts an HTTP test server implementing the RFC 6962 CT log interface.
func NewMockCTLogServer() (*MockCTLog, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	spkiBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	logID := sha256.Sum256(spkiBytes)

	mock := &MockCTLog{
		Key:   key,
		LogID: logID,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ct/v1/add-pre-chain", mock.handleAddPreChain)
	mock.Server = httptest.NewServer(mux)

	return mock, nil
}

// URL returns the base endpoint URL of the mock CT log server.
func (m *MockCTLog) URL() string {
	return m.Server.URL
}

// Close terminates the mock CT log HTTP server.
func (m *MockCTLog) Close() {
	m.Server.Close()
}

func (m *MockCTLog) handleAddPreChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AddChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Chain) < 2 {
		http.Error(w, "Bad Request: invalid chain", http.StatusBadRequest)
		return
	}

	// Decode PreCert and IssuerCert
	preCertDER, err := base64.StdEncoding.DecodeString(req.Chain[0])
	if err != nil {
		http.Error(w, "Bad Request: invalid base64 in pre-cert", http.StatusBadRequest)
		return
	}

	issuerDER, err := base64.StdEncoding.DecodeString(req.Chain[1])
	if err != nil {
		http.Error(w, "Bad Request: invalid base64 in issuer", http.StatusBadRequest)
		return
	}

	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		http.Error(w, "Bad Request: malformed issuer certificate", http.StatusBadRequest)
		return
	}

	issuerSPKI, err := x509.MarshalPKIXPublicKey(issuerCert.PublicKey)
	if err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	issuerKeyHash := sha256.Sum256(issuerSPKI)

	timestamp := uint64(time.Now().UnixMilli())

	// Assemble RFC 6962 §3.2 PrecertChainEntry signature payload
	// 1 (sct_version=0) + 1 (signature_type=0) + 8 (timestamp) + 2 (entry_type=1: precert) + 32 (issuer_key_hash) + 3 (len) + len(tbs) + 2 (exts len=0)
	tbsLen := len(preCertDER)
	sigInput := make([]byte, 1+1+8+2+32+3+tbsLen+2)
	offset := 0

	sigInput[offset] = 0 // sct_version = v1(0)
	offset++
	sigInput[offset] = 0 // signature_type = certificate_timestamp(0)
	offset++

	binary.BigEndian.PutUint64(sigInput[offset:offset+8], timestamp)
	offset += 8

	binary.BigEndian.PutUint16(sigInput[offset:offset+2], 1) // entry_type = precert_entry(1)
	offset += 2

	copy(sigInput[offset:offset+32], issuerKeyHash[:])
	offset += 32

	// 3-byte TBS length
	sigInput[offset] = byte(tbsLen >> 16)
	sigInput[offset+1] = byte(tbsLen >> 8)
	sigInput[offset+2] = byte(tbsLen)
	offset += 3

	copy(sigInput[offset:offset+tbsLen], preCertDER)
	offset += tbsLen

	// extensions length = 0
	binary.BigEndian.PutUint16(sigInput[offset:offset+2], 0)

	// Compute signature
	hash := sha256.Sum256(sigInput)
	asn1Sig, err := ecdsa.SignASN1(rand.Reader, m.Key, hash[:])
	if err != nil {
		http.Error(w, "Failed to sign", http.StatusInternalServerError)
		return
	}

	// DigitallySigned structure: 1 byte hash (sha256=4), 1 byte sig (ecdsa=3), 2 bytes length, asn1Sig
	digitallySigned := make([]byte, 1+1+2+len(asn1Sig))
	digitallySigned[0] = 4 // sha256
	digitallySigned[1] = 3 // ecdsa
	binary.BigEndian.PutUint16(digitallySigned[2:4], uint16(len(asn1Sig)))
	copy(digitallySigned[4:], asn1Sig)

	resp := AddChainResponse{
		SCTVersion: 0,
		ID:         base64.StdEncoding.EncodeToString(m.LogID[:]),
		Timestamp:  timestamp,
		Extensions: "",
		Signature:  base64.StdEncoding.EncodeToString(digitallySigned),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
