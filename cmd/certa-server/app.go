package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go-certa/pkg/audit"
	"go-certa/pkg/ca"
	"go-certa/pkg/protocols/acme"
	"go-certa/pkg/protocols/crl"
	"go-certa/pkg/protocols/est"
	"go-certa/pkg/protocols/ocsp"
	"go-certa/pkg/signer"
	"go-certa/pkg/storage"
	"go-certa/pkg/swagger"
	"go-certa/pkg/telemetry"
)

// AppConfig configures the go-certa trust authority server.
type AppConfig struct {
	ListenAddr              string
	BaseURL                 string
	DataDir                 string // Directory for sqlite DB, CA keys, and audit log. If empty, runs in-memory.
	AuditWriter             io.Writer
	SkipChallengeValidation bool
	AllowInternalDomains    bool // If true, permits internal/local TLDs like .local, .internal, localhost, etc.
	EnableSwagger           bool // If true, mounts Swagger UI at /swagger/ and OpenAPI spec at /swagger/doc.json
	CRLInterval             time.Duration
	CRLValidity             time.Duration
}

// ServerApp encapsulates all initialized PKI subsystem components and HTTP routing.
type ServerApp struct {
	Config        AppConfig
	Storage       storage.Storage
	Audit         *audit.ChainAuditLogger
	Telemetry     *telemetry.Registry
	Authority     *ca.Authority
	HSMSigner     cryptoSignerWrapper
	WorkerPool    *signer.WorkerPool
	CRLService    *crl.CRLService
	OCSPResponder *ocsp.Handler
	RevocationAPI *ocsp.RevocationAPI
	ACMEServer    *acme.Server
	ESTHandler    *est.Handler
	Mux           *http.ServeMux
	HTTPServer    *http.Server

	workerCancel context.CancelFunc
	auditCloser  io.Closer
}

type cryptoSignerWrapper struct {
	*signer.HSMSigner
}

// NewServerApp bootstraps the complete production-grade PKI stack.
func NewServerApp(cfg AppConfig) (*ServerApp, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:8080"
	}
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")

	auditWriter := cfg.AuditWriter
	if auditWriter == nil {
		auditWriter = os.Stdout
	}
	if cfg.CRLInterval <= 0 {
		cfg.CRLInterval = 1 * time.Hour
	}
	if cfg.CRLValidity <= 0 {
		cfg.CRLValidity = 24 * time.Hour
	}

	var store storage.Storage
	var authority *ca.Authority
	var hsmSigner *signer.HSMSigner
	var auditCloser io.Closer

	if cfg.DataDir != "" && cfg.DataDir != ":memory:" {
		if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
			return nil, fmt.Errorf("failed creating data dir: %w", err)
		}

		// 1. Persistent SQLite database
		dbPath := filepath.Join(cfg.DataDir, "certa.db")
		sqliteStore, err := storage.NewSQLiteStorage(dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed initializing sqlite storage: %w", err)
		}
		store = sqliteStore

		// 2. Persistent CA key and certificate hierarchy
		auth, signerInst, err := ca.LoadOrInitializeAuthority(cfg.DataDir, 15*time.Millisecond)
		if err != nil {
			return nil, fmt.Errorf("failed loading or initializing CA authority: %w", err)
		}
		authority = auth
		hsmSigner = signerInst

		// 3. Persistent audit log file (multi-writer with stdout)
		auditFile, err := os.OpenFile(filepath.Join(cfg.DataDir, "audit.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err == nil {
			auditWriter = io.MultiWriter(auditWriter, auditFile)
			auditCloser = auditFile
		}
	} else {
		// Ephemeral in-memory storage and CA
		store = storage.NewMemoryStorage()

		intKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed creating intermediate key: %w", err)
		}
		hsmSigner = signer.NewHSMSigner(intKey, 15*time.Millisecond)

		auth, err := ca.NewAuthority(hsmSigner)
		if err != nil {
			return nil, fmt.Errorf("failed initializing CA authority: %w", err)
		}
		authority = auth
	}

	if cfg.AllowInternalDomains || cfg.SkipChallengeValidation {
		authority.Policy.AllowInternalDomains = true
	}

	// 2. Initialize cryptographically chained audit logger
	auditLog := audit.NewChainAuditLogger(auditWriter)

	// 3. Initialize Prometheus telemetry registry
	metrics := telemetry.NewRegistry()

	// Record initial key access audit event
	_, _ = auditLog.LogEvent(
		context.Background(),
		audit.ActionKeyAccess,
		"system",
		authority.IntermediateCert.Subject.CommonName,
		audit.StatusSuccess,
		map[string]string{
			"root_subject": authority.RootCert.Subject.CommonName,
			"algorithm":    "RSA-2048",
		},
	)

	// 6. Initialize Worker Pool
	workerPool := signer.NewWorkerPool(authority, 1000, 16)

	// 7. Initialize CRL Generation & Distribution Service
	crlGen, err := crl.NewCRLGenerator(authority.IntermediateCert, hsmSigner, store, cfg.CRLValidity)
	if err != nil {
		return nil, fmt.Errorf("failed creating CRL generator: %w", err)
	}
	crlService := crl.NewCRLService(crlGen, cfg.CRLInterval)
	crlHandler := crl.NewHandler(crlService)

	// 8. Initialize High-Performance Delegated OCSP Responder
	ocspResponder, err := ocsp.NewResponder(ocsp.Config{
		IssuerCert:    authority.IntermediateCert,
		ResponderCert: authority.IntermediateCert,
		Signer:        hsmSigner,
		Storage:       store,
		CacheMaxAge:   3600,
		Validity:      24 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("failed initializing OCSP responder: %w", err)
	}

	// 9. Initialize Revocation Management API
	revocationAPI := ocsp.NewRevocationAPI(store)

	// 10. Initialize RFC 8555 ACME Server
	acmeServer, err := acme.NewServer(acme.ServerConfig{
		BaseURL:                 cfg.BaseURL,
		Authority:               authority,
		Storage:                 store,
		SkipChallengeValidation: cfg.SkipChallengeValidation,
	})
	if err != nil {
		return nil, fmt.Errorf("failed initializing ACME server: %w", err)
	}

	// 11. Initialize RFC 7030 EST Handler
	estHandler := est.NewHandler(workerPool, authority.IntermediateCert.Raw, store)

	// 12. Register all standard HTTP routes
	mux := http.NewServeMux()

	// RFC 8555 ACME routes
	mux.Handle("/.well-known/acme/", acmeServer)
	mux.Handle("/acme/", acmeServer)

	// RFC 7030 EST routes
	mux.HandleFunc("/.well-known/est/cacerts", estHandler.HandleCACerts)
	mux.HandleFunc("/.well-known/est/simpleenroll", estHandler.HandleSimpleEnroll)

	// RFC 6960 / RFC 5019 OCSP route
	mux.Handle("/ocsp", ocspResponder)

	// RFC 5280 CRL route
	mux.Handle("/crl/intermediate.crl", crlHandler)

	// Certificate Revocation Management API
	mux.HandleFunc("/api/v1/revoke", revocationAPI.HandleRevoke)

	// Prometheus telemetry route
	mux.Handle("/metrics", metrics.Handler())

	// Intermediate CA PEM block for ASCII downloads/views
	intermediatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.IntermediateCert.Raw})

	// RFC 5280 AIA caIssuers endpoint serving intermediate CA certificate (DER by default, PEM if requested)
	mux.HandleFunc("/ca/intermediate.crt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		format := strings.ToLower(r.URL.Query().Get("format"))
		accept := strings.ToLower(r.Header.Get("Accept"))
		if format == "pem" || strings.Contains(accept, "application/x-pem-file") || strings.Contains(accept, "text/plain") {
			w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			if r.Method == http.MethodHead {
				return
			}
			_, _ = w.Write(intermediatePEM)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(authority.IntermediateCert.Raw)
	})

	// Direct ASCII PEM endpoint for intermediate CA certificate
	mux.HandleFunc("/ca/intermediate.pem", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(intermediatePEM)
	})

	// Root CA PEM and full chain bundle
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.RootCert.Raw})
	chainPEM := append(append([]byte{}, intermediatePEM...), rootPEM...)

	// Root CA certificate endpoints (DER and PEM)
	mux.HandleFunc("/ca/root.crt", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		format := strings.ToLower(r.URL.Query().Get("format"))
		accept := strings.ToLower(r.Header.Get("Accept"))
		if format == "pem" || strings.Contains(accept, "application/x-pem-file") || strings.Contains(accept, "text/plain") {
			w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			if r.Method == http.MethodHead {
				return
			}
			_, _ = w.Write(rootPEM)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(authority.RootCert.Raw)
	})

	mux.HandleFunc("/ca/root.pem", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(rootPEM)
	})

	// Combined CA chain bundle (Intermediate + Root)
	mux.HandleFunc("/ca/chain.pem", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(chainPEM)
	})

	// Optional Swagger UI and OpenAPI 3.0 documentation
	if cfg.EnableSwagger {
		swaggerHandler := swagger.NewHandler()
		mux.Handle("/swagger/", swaggerHandler)
		mux.Handle("/swagger", swaggerHandler)
	}

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	app := &ServerApp{
		Config:        cfg,
		Storage:       store,
		Audit:         auditLog,
		Telemetry:     metrics,
		Authority:     authority,
		HSMSigner:     cryptoSignerWrapper{hsmSigner},
		WorkerPool:    workerPool,
		CRLService:    crlService,
		OCSPResponder: ocspResponder,
		RevocationAPI: revocationAPI,
		ACMEServer:    acmeServer,
		ESTHandler:    estHandler,
		Mux:           mux,
		HTTPServer:    server,
		auditCloser:   auditCloser,
	}

	return app, nil
}

// Start launches background services (WorkerPool, CRLService) and starts the HTTP listener.
func (app *ServerApp) Start(ctx context.Context) error {
	workerCtx, cancel := context.WithCancel(ctx)
	app.workerCancel = cancel

	// 1. Start worker pool
	go func() {
		if err := app.WorkerPool.Start(workerCtx); err != nil && err != context.Canceled {
			log.Printf("worker pool error: %v", err)
		}
	}()

	// 2. Start CRL background regeneration service
	if err := app.CRLService.Start(workerCtx); err != nil {
		return fmt.Errorf("failed starting CRL service: %w", err)
	}

	// 3. Periodic telemetry update
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-ticker.C:
				app.Telemetry.SetSigningQueueDepth(float64(app.WorkerPool.QueueDepth()))
			}
		}
	}()

	return nil
}

// Stop gracefully shuts down the HTTP server and stops background services.
func (app *ServerApp) Stop(ctx context.Context) error {
	var firstErr error

	// Stop HTTP server
	if app.HTTPServer != nil {
		if err := app.HTTPServer.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
			firstErr = err
		}
	}

	// Stop CRL background service
	if app.CRLService != nil {
		app.CRLService.Stop()
	}

	// Stop worker pool
	if app.workerCancel != nil {
		app.workerCancel()
	}

	// Close storage if closer
	if closer, ok := app.Storage.(io.Closer); ok {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Close audit log file if closer
	if app.auditCloser != nil {
		if err := app.auditCloser.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}
