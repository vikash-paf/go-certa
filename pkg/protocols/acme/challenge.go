package acme

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ChallengeValidator struct {
	client *http.Client
}

func NewChallengeValidator() *ChallengeValidator {
	return &ChallengeValidator{
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func ComputeKeyAuthorization(token string, keyThumbprint string) string {
	return fmt.Sprintf("%s.%s", token, keyThumbprint)
}

func (v *ChallengeValidator) ValidateHTTP01(domain, token, expectedKeyAuth string) error {
	url := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domain, token)

	resp, err := v.client.Get(url)
	if err != nil {
		return fmt.Errorf("http challenge connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed reading challenge response: %w", err)
	}

	actualKeyAuth := strings.TrimSpace(string(body))
	if actualKeyAuth != expectedKeyAuth {
		return fmt.Errorf("challenge mismatch: expected %s, got %s", expectedKeyAuth, actualKeyAuth)
	}

	return nil
}
