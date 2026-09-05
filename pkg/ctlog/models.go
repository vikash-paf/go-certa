package ctlog

import (
	"encoding/binary"
	"fmt"
)

// AddChainRequest is the JSON payload submitted to /ct/v1/add-pre-chain.
type AddChainRequest struct {
	Chain []string `json:"chain"` // Base64-encoded certificates
}

// AddChainResponse is the JSON response from /ct/v1/add-pre-chain.
type AddChainResponse struct {
	SCTVersion int    `json:"sct_version"`
	ID         string `json:"id"`         // Base64-encoded Log ID (32 bytes)
	Timestamp  uint64 `json:"timestamp"`  // Milliseconds since UNIX epoch
	Extensions string `json:"extensions"`  // Base64-encoded extensions
	Signature  string `json:"signature"`   // Base64-encoded DigitallySigned struct
}

// SignedCertificateTimestamp represents an RFC 6962 §3.2 SCT.
type SignedCertificateTimestamp struct {
	Version    uint8
	LogID      [32]byte
	Timestamp  uint64
	Extensions []byte
	HashAlgo   uint8 // e.g. 4 for SHA-256
	SigAlgo    uint8 // e.g. 3 for ECDSA, 1 for RSA
	Signature  []byte
}

// MarshalBinary serializes the SCT into the RFC 6962 §3.2 binary TLS presentation format.
func (sct *SignedCertificateTimestamp) MarshalBinary() ([]byte, error) {
	extLen := len(sct.Extensions)
	if extLen > 65535 {
		return nil, fmt.Errorf("extensions length %d exceeds 65535", extLen)
	}

	sigLen := len(sct.Signature)
	if sigLen > 65535 {
		return nil, fmt.Errorf("signature length %d exceeds 65535", sigLen)
	}

	// 1 (version) + 32 (logID) + 8 (timestamp) + 2 (extLen) + extLen + 1 (hashAlgo) + 1 (sigAlgo) + 2 (sigLen) + sigLen
	totalLen := 1 + 32 + 8 + 2 + extLen + 1 + 1 + 2 + sigLen
	buf := make([]byte, totalLen)

	offset := 0
	buf[offset] = sct.Version
	offset++

	copy(buf[offset:offset+32], sct.LogID[:])
	offset += 32

	binary.BigEndian.PutUint64(buf[offset:offset+8], sct.Timestamp)
	offset += 8

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(extLen))
	offset += 2
	if extLen > 0 {
		copy(buf[offset:offset+extLen], sct.Extensions)
		offset += extLen
	}

	buf[offset] = sct.HashAlgo
	offset++
	buf[offset] = sct.SigAlgo
	offset++

	binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(sigLen))
	offset += 2
	copy(buf[offset:offset+sigLen], sct.Signature)

	return buf, nil
}
