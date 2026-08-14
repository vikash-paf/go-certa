package signer

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"time"
)

// HSMSigner simulates a hardware security module with realistic cryptographic latency.
type HSMSigner struct {
	key     *rsa.PrivateKey
	latency time.Duration
}

// NewHSMSigner creates a mock HSM signer with simulated cryptographic latency.
func NewHSMSigner(key *rsa.PrivateKey, simulatedLatency time.Duration) *HSMSigner {
	return &HSMSigner{
		key:     key,
		latency: simulatedLatency,
	}
}

// Public returns the public key corresponding to the simulated HSM private key.
func (h *HSMSigner) Public() crypto.PublicKey {
	return h.key.Public()
}

// Sign signs a digest using the private key inside the HSM, simulating hardware delay.
func (h *HSMSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if h.key == nil {
		return nil, fmt.Errorf("hsm session uninitialized")
	}
	// Simulate cryptographic calculation latency on dedicated hardware
	if h.latency > 0 {
		time.Sleep(h.latency)
	}
	return h.key.Sign(rand, digest, opts)
}
