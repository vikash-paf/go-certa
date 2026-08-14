package acme

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateHTTP01(t *testing.T) {
	token := "xyz-token"
	keyAuth := ComputeKeyAuthorization(token, "thumbprint")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/.well-known/acme-challenge/" + token
		if r.URL.Path != expectedPath {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(keyAuth))
	}))
	defer server.Close()

	host := server.URL[len("http://"):]

	validator := NewChallengeValidator()
	err := validator.ValidateHTTP01(host, token, keyAuth)
	if err != nil {
		t.Fatalf("unexpected validation failure: %v", err)
	}

	err = validator.ValidateHTTP01(host, token, "wrong-key-auth")
	if err == nil {
		t.Fatal("expected error due to mismatched key auth, got nil")
	}
}
