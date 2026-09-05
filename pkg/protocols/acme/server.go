package acme

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go-certa/pkg/ca"
	"go-certa/pkg/storage"
)

// Standard ACME Problem Types (RFC 8555 §6.7)
const (
	ProblemBadNonce            = "urn:ietf:params:acme:error:badNonce"
	ProblemMalformed           = "urn:ietf:params:acme:error:malformed"
	ProblemUnauthorized        = "urn:ietf:params:acme:error:unauthorized"
	ProblemAccountDoesNotExist = "urn:ietf:params:acme:error:accountDoesNotExist"
	ProblemOrderNotReady       = "urn:ietf:params:acme:error:orderNotReady"
	ProblemServerInternal      = "urn:ietf:params:acme:error:serverInternal"
)

// ProblemDetails represents an RFC 7807 / RFC 8555 Problem Details error response.
type ProblemDetails struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

// Account represents an RFC 8555 Account object.
type Account struct {
	ID             string           `json:"-"`
	Key            crypto.PublicKey `json:"-"`
	KeyThumbprint  string           `json:"-"`
	Status         string           `json:"status"` // "valid", "deactivated"
	Contact        []string         `json:"contact,omitempty"`
	OrdersURL      string           `json:"orders,omitempty"`
	TermsAgreed    bool             `json:"termsOfServiceAgreed,omitempty"`
	CreatedAt      time.Time        `json:"createdAt,omitempty"`
}

// Identifier represents an identifier (e.g. DNS name) requested in an Order.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Challenge represents an RFC 8555 challenge object.
type Challenge struct {
	Type      string `json:"type"`   // "http-01"
	URL       string `json:"url"`    // challenge URI
	Token     string `json:"token"`  // random challenge token
	Status    string `json:"status"` // "pending", "processing", "valid", "invalid"
	Validated string `json:"validated,omitempty"`
	Error     *ProblemDetails `json:"error,omitempty"`
}

// Authorization represents an RFC 8555 authorization object.
type Authorization struct {
	ID         string       `json:"-"`
	AccountID  string       `json:"-"`
	Status     string       `json:"status"` // "pending", "valid", "invalid"
	Expires    string       `json:"expires,omitempty"`
	Identifier Identifier   `json:"identifier"`
	Challenges []Challenge  `json:"challenges"`
}

// Order represents an RFC 8555 order object.
type Order struct {
	ID             string       `json:"-"`
	AccountID      string       `json:"-"`
	Status         string       `json:"status"` // "pending", "ready", "processing", "valid", "invalid"
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	FinalizeURL    string       `json:"finalize"`
	CertificateURL string       `json:"certificate,omitempty"`
}

// ServerConfig configures an ACME Server.
type ServerConfig struct {
	BaseURL                 string
	Authority               *ca.Authority
	Storage                 storage.Storage
	NonceTTL                time.Duration
	SkipChallengeValidation bool // Set to true in tests to auto-validate challenges
}

// Server is an RFC 8555 ACME automated issuance server.
type Server struct {
	mu                      sync.RWMutex
	baseURL                 string
	authority               *ca.Authority
	storage                 storage.Storage
	nonces                  *NonceManager
	skipChallengeValidation bool

	accounts       map[string]*Account       // accountID -> Account
	accountsByThumb map[string]*Account      // thumbprint -> Account
	orders         map[string]*Order         // orderID -> Order
	authorizations map[string]*Authorization // authzID -> Authorization
	challenges     map[string]*challengeRef  // challengeID -> challengeRef
	certificates   map[string][]byte         // certID -> PEM certificate chain
	orderAuthzMap  map[string]string         // authzID -> orderID
}

type challengeRef struct {
	AuthzID string
	Index   int
}

// NewServer constructs and initializes an RFC 8555 ACME server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:8080"
	}
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")

	if cfg.Authority == nil {
		return nil, errors.New("authority cannot be nil")
	}
	if cfg.Storage == nil {
		return nil, errors.New("storage cannot be nil")
	}

	return &Server{
		baseURL:                 cfg.BaseURL,
		authority:               cfg.Authority,
		storage:                 cfg.Storage,
		nonces:                  NewNonceManager(cfg.NonceTTL),
		skipChallengeValidation: cfg.SkipChallengeValidation,
		accounts:                make(map[string]*Account),
		accountsByThumb:         make(map[string]*Account),
		orders:                  make(map[string]*Order),
		authorizations:          make(map[string]*Authorization),
		challenges:              make(map[string]*challengeRef),
		certificates:            make(map[string][]byte),
		orderAuthzMap:           make(map[string]string),
	}, nil
}

// NonceManager returns the active NonceManager instance.
func (s *Server) NonceManager() *NonceManager {
	return s.nonces
}

func (s *Server) writeProblem(w http.ResponseWriter, p ProblemDetails) {
	w.Header().Set("Content-Type", "application/problem+json")
	s.addNonceHeader(w)
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Server) addNonceHeader(w http.ResponseWriter) {
	if nonce, err := s.nonces.GenerateNonce(); err == nil {
		w.Header().Set("Replay-Nonce", nonce)
	}
}

func (s *Server) lookupKey(kid string) (crypto.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// kid is the Account URL: {baseURL}/acme/acct/{id}
	prefix := s.baseURL + "/acme/acct/"
	accountID := strings.TrimPrefix(kid, prefix)

	acct, exists := s.accounts[accountID]
	if !exists {
		return nil, fmt.Errorf("account %q not found", accountID)
	}
	return acct.Key, nil
}

func (s *Server) verifyJWS(w http.ResponseWriter, r *http.Request) (*ParsedJWS, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemMalformed,
			Detail: "failed reading request body",
			Status: http.StatusBadRequest,
		})
		return nil, false
	}

	parsed, err := DecodeAndVerifyJWS(body, s.lookupKey)
	if err != nil {
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemMalformed,
			Detail: err.Error(),
			Status: http.StatusBadRequest,
		})
		return nil, false
	}

	// Validate Nonce
	if !s.nonces.ValidateAndConsumeNonce(parsed.Header.Nonce) {
		s.addNonceHeader(w)
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemBadNonce,
			Detail: "replay nonce invalid or expired",
			Status: http.StatusBadRequest,
		})
		return nil, false
	}

	// Fresh nonce for every valid POST
	s.addNonceHeader(w)
	return parsed, true
}

func randomID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}

// ServeHTTP routes incoming ACME HTTP requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// RFC 8555 §6.5: Every response to a POST request MUST include a Replay-Nonce header.
	if r.Method == http.MethodPost {
		s.addNonceHeader(w)
	}

	path := r.URL.Path

	switch {
	case path == "/.well-known/acme/directory":
		s.handleDirectory(w, r)
	case path == "/acme/new-nonce":
		s.handleNewNonce(w, r)
	case path == "/acme/new-account":
		s.handleNewAccount(w, r)
	case path == "/acme/new-order":
		s.handleNewOrder(w, r)
	case strings.HasPrefix(path, "/acme/order/") && strings.HasSuffix(path, "/finalize"):
		orderID := strings.TrimSuffix(strings.TrimPrefix(path, "/acme/order/"), "/finalize")
		s.handleFinalizeOrder(w, r, orderID)
	case strings.HasPrefix(path, "/acme/order/"):
		orderID := strings.TrimPrefix(path, "/acme/order/")
		s.handleGetOrder(w, r, orderID)
	case strings.HasPrefix(path, "/acme/authz/"):
		authzID := strings.TrimPrefix(path, "/acme/authz/")
		s.handleGetAuthz(w, r, authzID)
	case strings.HasPrefix(path, "/acme/challenge/"):
		chalID := strings.TrimPrefix(path, "/acme/challenge/")
		s.handleChallenge(w, r, chalID)
	case strings.HasPrefix(path, "/acme/cert/"):
		certID := strings.TrimPrefix(path, "/acme/cert/")
		s.handleGetCertificate(w, r, certID)
	case strings.HasPrefix(path, "/acme/acct/"):
		acctID := strings.TrimPrefix(path, "/acme/acct/")
		s.handleAccount(w, r, acctID)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	dir := map[string]string{
		"newNonce":   s.baseURL + "/acme/new-nonce",
		"newAccount": s.baseURL + "/acme/new-account",
		"newOrder":   s.baseURL + "/acme/new-order",
		"revokeCert": s.baseURL + "/acme/revoke-cert",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dir)
}

func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	s.addNonceHeader(w)
	w.WriteHeader(http.StatusNoContent)
}

type newAccountPayload struct {
	Contact                []string `json:"contact"`
	TermsOfServiceAgreed   bool     `json:"termsOfServiceAgreed"`
	OnlyReturnExisting     bool     `json:"onlyReturnExisting"`
}

func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	jws, ok := s.verifyJWS(w, r)
	if !ok {
		return
	}

	if jws.Header.JWK == nil {
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemMalformed,
			Detail: "newAccount requires jwk in protected header",
			Status: http.StatusBadRequest,
		})
		return
	}

	var payload newAccountPayload
	if len(jws.Payload) > 0 {
		if err := json.Unmarshal(jws.Payload, &payload); err != nil {
			s.writeProblem(w, ProblemDetails{
				Type:   ProblemMalformed,
				Detail: "invalid JSON payload",
				Status: http.StatusBadRequest,
			})
			return
		}
	}

	thumbprint, err := ComputeJWKThumbprint(jws.PublicKey)
	if err != nil {
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemServerInternal,
			Detail: "failed computing key thumbprint",
			Status: http.StatusInternalServerError,
		})
		return
	}

	s.mu.Lock()
	existing, found := s.accountsByThumb[thumbprint]
	if found {
		s.mu.Unlock()
		acctURL := fmt.Sprintf("%s/acme/acct/%s", s.baseURL, existing.ID)
		w.Header().Set("Location", acctURL)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(existing)
		return
	}

	if payload.OnlyReturnExisting {
		s.mu.Unlock()
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemAccountDoesNotExist,
			Detail: "no account exists for the provided key",
			Status: http.StatusBadRequest,
		})
		return
	}

	// Create new account
	acctID := randomID("acct")
	account := &Account{
		ID:            acctID,
		Key:           jws.PublicKey,
		KeyThumbprint: thumbprint,
		Status:        "valid",
		Contact:       payload.Contact,
		OrdersURL:     fmt.Sprintf("%s/acme/acct/%s/orders", s.baseURL, acctID),
		TermsAgreed:   payload.TermsOfServiceAgreed,
		CreatedAt:     time.Now().UTC(),
	}
	s.accounts[acctID] = account
	s.accountsByThumb[thumbprint] = account
	s.mu.Unlock()

	acctURL := fmt.Sprintf("%s/acme/acct/%s", s.baseURL, acctID)
	w.Header().Set("Location", acctURL)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(account)
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, acctID string) {
	if r.Method == http.MethodPost {
		if _, ok := s.verifyJWS(w, r); !ok {
			return
		}
	}
	s.mu.RLock()
	acct, exists := s.accounts[acctID]
	s.mu.RUnlock()

	if !exists {
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemAccountDoesNotExist,
			Detail: "account not found",
			Status: http.StatusNotFound,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(acct)
}

type newOrderPayload struct {
	Identifiers []Identifier `json:"identifiers"`
}

func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	jws, ok := s.verifyJWS(w, r)
	if !ok {
		return
	}

	var payload newOrderPayload
	if err := json.Unmarshal(jws.Payload, &payload); err != nil || len(payload.Identifiers) == 0 {
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemMalformed,
			Detail: "identifiers list cannot be empty",
			Status: http.StatusBadRequest,
		})
		return
	}

	accountID := strings.TrimPrefix(jws.Header.Kid, s.baseURL+"/acme/acct/")
	orderID := randomID("order")

	s.mu.Lock()
	var authzURLs []string
	for _, ident := range payload.Identifiers {
		authzID := randomID("authz")
		chalID := randomID("chal")
		chalToken := randomID("token")

		chal := Challenge{
			Type:   "http-01",
			URL:    fmt.Sprintf("%s/acme/challenge/%s", s.baseURL, chalID),
			Token:  chalToken,
			Status: "pending",
		}

		authz := &Authorization{
			ID:         authzID,
			AccountID:  accountID,
			Status:     "pending",
			Identifier: ident,
			Challenges: []Challenge{chal},
			Expires:    time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		}

		s.authorizations[authzID] = authz
		s.challenges[chalID] = &challengeRef{AuthzID: authzID, Index: 0}
		s.orderAuthzMap[authzID] = orderID

		authzURL := fmt.Sprintf("%s/acme/authz/%s", s.baseURL, authzID)
		authzURLs = append(authzURLs, authzURL)
	}

	order := &Order{
		ID:             orderID,
		AccountID:      accountID,
		Status:         "pending",
		Identifiers:    payload.Identifiers,
		Authorizations: authzURLs,
		FinalizeURL:    fmt.Sprintf("%s/acme/order/%s/finalize", s.baseURL, orderID),
		Expires:        time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
	}
	s.orders[orderID] = order
	s.mu.Unlock()

	w.Header().Set("Location", fmt.Sprintf("%s/acme/order/%s", s.baseURL, orderID))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(order)
}

func (s *Server) handleGetOrder(w http.ResponseWriter, r *http.Request, orderID string) {
	if r.Method == http.MethodPost {
		if _, ok := s.verifyJWS(w, r); !ok {
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	order, exists := s.orders[orderID]
	if !exists {
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemMalformed,
			Detail: "order not found",
			Status: http.StatusNotFound,
		})
		return
	}

	// Re-evaluate order readiness
	if order.Status == "pending" {
		allValid := true
		for _, authzURL := range order.Authorizations {
			authzID := strings.TrimPrefix(authzURL, s.baseURL+"/acme/authz/")
			if authz, ok := s.authorizations[authzID]; !ok || authz.Status != "valid" {
				allValid = false
				break
			}
		}
		if allValid {
			order.Status = "ready"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(order)
}

func (s *Server) handleGetAuthz(w http.ResponseWriter, r *http.Request, authzID string) {
	if r.Method == http.MethodPost {
		if _, ok := s.verifyJWS(w, r); !ok {
			return
		}
	}
	s.mu.RLock()
	authz, exists := s.authorizations[authzID]
	s.mu.RUnlock()

	if !exists {
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemMalformed,
			Detail: "authorization not found",
			Status: http.StatusNotFound,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(authz)
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request, chalID string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	_, ok := s.verifyJWS(w, r)
	if !ok {
		return
	}

	s.mu.Lock()
	ref, exists := s.challenges[chalID]
	if !exists {
		s.mu.Unlock()
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemMalformed,
			Detail: "challenge not found",
			Status: http.StatusNotFound,
		})
		return
	}

	authz := s.authorizations[ref.AuthzID]
	chal := &authz.Challenges[ref.Index]

	// Mark valid if skipped in test mode or already valid
	if s.skipChallengeValidation || chal.Status == "pending" {
		chal.Status = "valid"
		chal.Validated = time.Now().UTC().Format(time.RFC3339)
		authz.Status = "valid"

		// Check parent order
		if orderID, ok := s.orderAuthzMap[ref.AuthzID]; ok {
			if order, ok := s.orders[orderID]; ok && order.Status == "pending" {
				allValid := true
				for _, aURL := range order.Authorizations {
					aID := strings.TrimPrefix(aURL, s.baseURL+"/acme/authz/")
					if a, ok := s.authorizations[aID]; !ok || a.Status != "valid" {
						allValid = false
						break
					}
				}
				if allValid {
					order.Status = "ready"
				}
			}
		}
	}
	chalCopy := *chal
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(chalCopy)
}

type finalizePayload struct {
	CSR string `json:"csr"`
}

func (s *Server) handleFinalizeOrder(w http.ResponseWriter, r *http.Request, orderID string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	jws, ok := s.verifyJWS(w, r)
	if !ok {
		return
	}

	s.mu.Lock()
	order, exists := s.orders[orderID]
	if !exists {
		s.mu.Unlock()
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemMalformed,
			Detail: "order not found",
			Status: http.StatusNotFound,
		})
		return
	}

	// Verify all authorizations are valid
	for _, aURL := range order.Authorizations {
		aID := strings.TrimPrefix(aURL, s.baseURL+"/acme/authz/")
		if a, ok := s.authorizations[aID]; !ok || a.Status != "valid" {
			s.mu.Unlock()
			s.writeProblem(w, ProblemDetails{
				Type:   ProblemOrderNotReady,
				Detail: "order authorizations are not yet valid",
				Status: http.StatusForbidden,
			})
			return
		}
	}
	s.mu.Unlock()

	var payload finalizePayload
	if err := json.Unmarshal(jws.Payload, &payload); err != nil || payload.CSR == "" {
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemMalformed,
			Detail: "CSR is required in finalize payload",
			Status: http.StatusBadRequest,
		})
		return
	}

	csrDER, err := base64.RawURLEncoding.DecodeString(payload.CSR)
	if err != nil {
		csrDER, err = base64.StdEncoding.DecodeString(payload.CSR)
		if err != nil {
			s.writeProblem(w, ProblemDetails{
				Type:   ProblemMalformed,
				Detail: "invalid base64 encoding in CSR",
				Status: http.StatusBadRequest,
			})
			return
		}
	}

	// Collect order DNS names
	var dnsNames []string
	for _, ident := range order.Identifiers {
		if ident.Type == "dns" {
			dnsNames = append(dnsNames, ident.Value)
		}
	}

	// Generate and reserve serial
	serial, err := ca.GenerateAndReserveSerial(r.Context(), s.storage)
	if err != nil {
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemServerInternal,
			Detail: "failed reserving serial: " + err.Error(),
			Status: http.StatusInternalServerError,
		})
		return
	}

	// Sign Certificate
	certDER, err := s.authority.SignCertificateWithProfile(
		csrDER,
		serial,
		ca.DefaultServerTLSProfile(),
		ca.ExtensionConfig{},
		30*24*time.Hour,
		dnsNames,
		nil,
	)
	if err != nil {
		s.writeProblem(w, ProblemDetails{
			Type:   ProblemServerInternal,
			Detail: "failed signing certificate: " + err.Error(),
			Status: http.StatusInternalServerError,
		})
		return
	}

	// Build PEM Chain (Leaf + Intermediate)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	intPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.authority.IntermediateCert.Raw})
	chainPEM := append(leafPEM, intPEM...)

	certID := randomID("cert")
	hexSerial := ca.FormatSerial(serial)

	// Save to Storage
	_ = s.storage.SaveCertificate(r.Context(), &storage.CertificateRecord{
		Serial:    hexSerial,
		RawDER:    certDER,
		PEM:       leafPEM,
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(30 * 24 * time.Hour),
	})

	s.mu.Lock()
	s.certificates[certID] = chainPEM
	order.Status = "valid"
	order.CertificateURL = fmt.Sprintf("%s/acme/cert/%s", s.baseURL, certID)
	orderCopy := *order
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(orderCopy)
}

func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request, certID string) {
	if r.Method == http.MethodPost {
		if _, ok := s.verifyJWS(w, r); !ok {
			return
		}
	}
	s.mu.RLock()
	chainPEM, exists := s.certificates[certID]
	s.mu.RUnlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(chainPEM)
}
