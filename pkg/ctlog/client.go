package ctlog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CTSubmitter submits pre-certificates to a Certificate Transparency log.
type CTSubmitter struct {
	URL    string
	Client *http.Client
}

// NewCTSubmitter constructs a CTSubmitter for the given log endpoint URL.
func NewCTSubmitter(url string, client *http.Client) *CTSubmitter {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &CTSubmitter{
		URL:    strings.TrimSuffix(url, "/"),
		Client: client,
	}
}

// SubmitPreCertificate submits the pre-certificate and issuer chain to the CT log and returns the raw SCT bytes.
func (c *CTSubmitter) SubmitPreCertificate(ctx context.Context, preCertDER []byte, issuerCertDER []byte) ([]byte, error) {
	if len(preCertDER) == 0 || len(issuerCertDER) == 0 {
		return nil, errors.New("preCertDER and issuerCertDER cannot be empty")
	}

	reqBody := AddChainRequest{
		Chain: []string{
			base64.StdEncoding.EncodeToString(preCertDER),
			base64.StdEncoding.EncodeToString(issuerCertDER),
		},
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling add-pre-chain request: %w", err)
	}

	endpoint := c.URL + "/ct/v1/add-pre-chain"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed creating HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.Client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request to CT log failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("CT log returned status %d: %s", httpResp.StatusCode, string(respBytes))
	}

	var addResp AddChainResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&addResp); err != nil {
		return nil, fmt.Errorf("failed decoding CT log JSON response: %w", err)
	}

	logID, err := base64.StdEncoding.DecodeString(addResp.ID)
	if err != nil || len(logID) != 32 {
		return nil, fmt.Errorf("invalid log ID in CT response: %v", err)
	}

	var extBytes []byte
	if addResp.Extensions != "" {
		extBytes, err = base64.StdEncoding.DecodeString(addResp.Extensions)
		if err != nil {
			return nil, fmt.Errorf("invalid extensions in CT response: %w", err)
		}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(addResp.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature in CT response: %w", err)
	}

	// Pack into RFC 6962 §3.2 binary SignedCertificateTimestamp format
	totalLen := 1 + 32 + 8 + 2 + len(extBytes) + len(sigBytes)
	sctBytes := make([]byte, totalLen)

	sctBytes[0] = uint8(addResp.SCTVersion)
	copy(sctBytes[1:33], logID)
	binary.BigEndian.PutUint64(sctBytes[33:41], addResp.Timestamp)
	binary.BigEndian.PutUint16(sctBytes[41:43], uint16(len(extBytes)))
	copy(sctBytes[43:43+len(extBytes)], extBytes)
	copy(sctBytes[43+len(extBytes):], sigBytes)

	return sctBytes, nil
}
